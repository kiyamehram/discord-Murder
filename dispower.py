from flask import Flask, request, redirect, Response, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import logging
from logging.handlers import RotatingFileHandler
import urllib.parse
import os
import sys
from functools import wraps
from http import HTTPStatus
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from datetime import datetime, timedelta
import re
import socket
import configparser
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge
import argparse
import ssl
import json
import redis
import geoip2.database
import hashlib
import asyncio
import aiohttp
import jwt
from ua_parser import user_agent_parser
from typing import Dict, Any, Optional
import time
from cachetools import TTLCache
from ratelimit import limits, RateLimitException
import hmac
import base64
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor

load_dotenv()

trace.set_tracer_provider(TracerProvider())
jaeger_exporter = JaegerExporter(
    agent_host_name="localhost",
    agent_port=6831,
)
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(jaeger_exporter))
tracer = trace.get_tracer(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=2, x_host=1, x_prefix=1)
FlaskInstrumentor().instrument_app(app)

cache = TTLCache(maxsize=1000, ttl=300)

CORS(app, resources={
    r"/*": {
        "origins": os.getenv("ALLOWED_ORIGINS", "*").split(","),
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Request-ID", "Authorization", "X-Signature"],
        "supports_credentials": True,
        "max_age": 86400
    }
})

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        RotatingFileHandler('app.log', maxBytes=10000000, backupCount=20),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

redis_pool = redis.ConnectionPool.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True,
    max_connections=100
)
redis_client = redis.Redis(connection_pool=redis_pool)

try:
    geoip_reader = geoip2.database.Reader(os.getenv('GEOIP_DB_PATH', 'GeoLite2-City.mmdb'))
except Exception as e:
    logger.error(f"Failed to load GeoIP database: {str(e)}")
    geoip_reader = None

REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP Request Duration', ['endpoint'])
BOT_ATTEMPTS = Counter('bot_attempts_total', 'Suspected Bot Attempts', ['endpoint'])
ACTIVE_CONNECTIONS = Gauge('active_connections', 'Number of active connections')
CACHE_HITS = Counter('cache_hits_total', 'Cache Hits', ['endpoint'])
REQUEST_SIZE = Histogram('request_size_bytes', 'Request Size in Bytes', ['endpoint'])

def load_config():
    config = configparser.ConfigParser()
    config_file = 'config.ini'
    
    default_config = {
        'Server': {
            'host': os.getenv('HOST', '0.0.0.0'),
            'port': os.getenv('PORT', '5000'),
            'ssl_cert': os.getenv('SSL_CERT', ''),
            'ssl_key': os.getenv('SSL_KEY', ''),
            'workers': os.getenv('WORKERS', '16'),
            'timeout': os.getenv('TIMEOUT', '120'),
            'jwt_secret': os.getenv('JWT_SECRET', os.urandom(32).hex()),
            'hmac_secret': os.getenv('HMAC_SECRET', os.urandom(32).hex()),
        },
        'Security': {
            'allowed_domains': os.getenv('ALLOWED_DOMAINS', 'cdn.discordapp.com,media.discordapp.net,discord.com,discordapp.com'),
            'max_url_length': os.getenv('MAX_URL_LENGTH', '2048'),
            'require_captcha': os.getenv('REQUIRE_CAPTCHA', 'false').lower() == 'true',
            'max_request_size': os.getenv('MAX_REQUEST_SIZE', '1024'),
            'jwt_expiry': os.getenv('JWT_EXPIRY', '3600'),
        },
        'Tracking': {
            'enable_geoip': os.getenv('ENABLE_GEOIP', 'true').lower() == 'true',
            'track_headers': os.getenv('TRACK_HEADERS', 'User-Agent,Referer,Accept-Language,X-Forwarded-For'),
            'log_sensitive_data': os.getenv('LOG_SENSITIVE_DATA', 'false').lower() == 'true',
            'retention_days': os.getenv('RETENTION_DAYS', '30')
        },
        'RateLimiting': {
            'default_limit': os.getenv('DEFAULT_RATE_LIMIT', '100 per minute'),
            'bot_limit': os.getenv('BOT_RATE_LIMIT', '10 per minute'),
            'ip_blocklist': os.getenv('IP_BLOCKLIST', '')
        }
    }
    
    if os.path.exists(config_file):
        config.read(config_file)
    else:
        config.read_dict(default_config)
        with open(config_file, 'w') as f:
            config.write(f)
    
    return config

config = load_config()

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[config['RateLimiting']['default_limit']],
    storage_uri=os.getenv("REDIS_URL", "redis://localhost:6379")
)

def verify_request_signature(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        signature = request.headers.get('X-Signature')
        if not signature:
            return jsonify({'error': 'Missing signature'}), HTTPStatus.UNAUTHORIZED
        
        expected_signature = hmac.new(
            config['Server']['hmac_secret'].encode(),
            request.get_data(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({'error': 'Invalid signature'}), HTTPStatus.UNAUTHORIZED
        
        return await f(*args, **kwargs) if asyncio.iscoroutinefunction(f) else f(*args, **kwargs)
    return decorated

def add_security_headers(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        with tracer.start_as_current_span(f.__name__):
            start_time = datetime.now()
            ACTIVE_CONNECTIONS.inc()
            
            try:
                resp = await f(*args, **kwargs) if asyncio.iscoroutinefunction(f) else f(*args, **kwargs)
                if isinstance(resp, Response):
                    resp.headers.update({
                        'X-Content-Type-Options': 'nosniff',
                        'X-Frame-Options': 'DENY',
                        'X-XSS-Protection': '1; mode=block',
                        'Content-Security-Policy': (
                            "default-src 'none'; "
                            "connect-src 'self' https://api.ipify.org https://*.discordapp.com; "
                            "img-src 'self' data: https://*.discordapp.com https://*.discord.com;"
                            "script-src 'self' 'unsafe-eval';"
                            "style-src 'self' 'unsafe-inline';"
                            "frame-ancestors 'none';"
                        ),
                        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
                        'Referrer-Policy': 'strict-origin-when-cross-origin',
                        'Permissions-Policy': (
                            'geolocation=(self), microphone=(), camera=(), interest-cohort=()'
                        ),
                        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        'Pragma': 'no-cache'
                    })
                    
                    REQUEST_COUNT.labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status=resp.status_code
                    ).inc()
                    
                    duration = (datetime.now() - start_time).total_seconds()
                    REQUEST_LATENCY.labels(endpoint=request.endpoint or 'unknown').observe(duration)
                    REQUEST_SIZE.labels(endpoint=request.endpoint or 'unknown').observe(len(request.data))
                
                return resp
            except Exception as e:
                logger.error(f"Error in {f.__name__}: {str(e)}", exc_info=True)
                raise
            finally:
                ACTIVE_CONNECTIONS.dec()
    return decorated

ALLOWED_DOMAINS = re.compile(
    r'^(https?://)?(' + '|'.join(
        re.escape(domain) for domain in config['Security']['allowed_domains'].split(',')
    ) + ')/.*$'
)

def is_allowed_url(url: str) -> bool:
    if len(url) > int(config['Security']['max_url_length']):
        return False
    return bool(ALLOWED_DOMAINS.match(url))

def is_suspected_bot() -> bool:
    user_agent = request.headers.get('User-Agent', '').lower()
    bot_patterns = [
        'bot', 'crawler', 'spider', 'slurp', 'google', 'bing', 'yandex',
        'scrapy', 'headless', 'phantomjs', 'python-requests', 'curl'
    ]
    
    suspicious_headers = [
        not request.headers.get('Accept'),
        not request.headers.get('Accept-Language'),
        'Headless' in request.headers.get('User-Agent', '')
    ]
    
    return any(pattern in user_agent for pattern in bot_patterns) or any(suspicious_headers)

def hash_sensitive_data(data: str) -> str:
    if config['Tracking']['log_sensitive_data'].lower() == 'false':
        return hashlib.sha256(data.encode()).hexdigest()
    return data

async def get_geoip_data(ip: str) -> Dict[str, Any]:
    if not config['Tracking']['enable_geoip'] or not geoip_reader:
        return {}
    
    cache_key = f"geoip:{ip}"
    cached_result = cache.get(cache_key)
    if cached_result:
        CACHE_HITS.labels(endpoint='geoip').inc()
        return cached_result
    
    try:
        response = geoip_reader.city(ip)
        geo_data = {
            'country': response.country.name,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'isp': response.traits.isp,
            'asn': response.traits.autonomous_system_number
        }
        cache[cache_key] = geo_data
        return geo_data
    except Exception as e:
        logger.error(f"GeoIP lookup failed for IP {ip}: {str(e)}")
        return {}

async def validate_captcha(token: str) -> bool:
    if not config['Security']['require_captcha']:
        return True
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': os.getenv('RECAPTCHA_SECRET'),
                    'response': token
                }
            ) as response:
                result = await response.json()
                return result.get('success', False)
        except Exception as e:
            logger.error(f"Captcha validation failed: {str(e)}")
            return False

@app.errorhandler(Exception)
def handle_error(error):
    status = HTTPStatus.INTERNAL_SERVER_ERROR
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.endpoint or 'unknown',
        status=status
    ).inc()
    
    logger.error(f"Unhandled error: {str(error)}", exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'timestamp': datetime.utcnow().isoformat(),
        'request_id': request.headers.get('X-Request-ID', 'N/A'),
        'trace_id': trace.get_current_span().get_span_context().trace_id
    }), status

@app.errorhandler(RateLimitException)
def ratelimit_handler(e):
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.endpoint or 'unknown',
        status=429
    ).inc()
    
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': str(e),
        'timestamp': datetime.utcnow().isoformat(),
        'request_id': request.headers.get('X-Request-ID', 'N/A'),
        'trace_id': trace.get_current_span().get_span_context().trace_id
    }), HTTPStatus.TOO_MANY_REQUESTS

@app.errorhandler(404)
def not_found(e):
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.endpoint or 'unknown',
        status=404
    ).inc()
    
    return jsonify({
        'error': 'Resource not found',
        'timestamp': datetime.utcnow().isoformat(),
        'request_id': request.headers.get('X-Request-ID', 'N/A'),
        'trace_id': trace.get_current_span().get_span_context().trace_id
    }), HTTPStatus.NOT_FOUND

@app.route('/health')
@add_security_headers
@limiter.exempt
def health_check():
    redis_status = redis_client.ping() if redis_client else False
    return jsonify({
        'status': 'healthy' if redis_status else 'degraded',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.1.0',
        'uptime': (datetime.now() - app.start_time).total_seconds(),
        'redis_status': 'connected' if redis_status else 'disconnected',
        'geoip_enabled': bool(geoip_reader and config['Tracking']['enable_geoip']),
        'active_connections': ACTIVE_CONNECTIONS._value.get(),
        'cache_size': len(cache)
    }), HTTPStatus.OK

@app.route('/metrics')
@add_security_headers
@limiter.exempt
def metrics():
    return Response(
        prometheus_client.generate_latest(),
        mimetype='text/plain; version=0.0.4; charset=utf-8'
    )

@app.route('/track', methods=['GET'])
@add_security_headers
@verify_request_signature
@limits(calls=100, period=60)
async def track_and_redirect():
    with tracer.start_as_current_span("track_and_redirect"):
        try:
            start_time = time.time()
            
            client_ip = get_remote_address()
            if client_ip in config['RateLimiting']['ip_blocklist'].split(','):
                return jsonify({
                    'error': 'IP blocked',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.FORBIDDEN

            if is_suspected_bot():
                BOT_ATTEMPTS.labels(endpoint='track').inc()
                logger.warning(f"Suspected bot detected: {client_ip}")
                return jsonify({
                    'error': 'Bot activity detected',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.FORBIDDEN

            captcha_token = request.headers.get('X-Captcha-Token')
            if config['Security']['require_captcha'] and not await validate_captcha(captcha_token):
                return jsonify({
                    'error': 'Invalid captcha',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.FORBIDDEN

            original_url = request.args.get('url')
            if not original_url:
                return jsonify({
                    'error': 'No URL provided',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.BAD_REQUEST
            
            original_url = urllib.parse.unquote(original_url)
            if not original_url.startswith(('http://', 'https://')):
                return jsonify({
                    'error': 'Invalid URL scheme',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.BAD_REQUEST

            if not is_allowed_url(original_url):
                return jsonify({
                    'error': 'URL domain not allowed',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.FORBIDDEN

            # Check request size
            if len(request.data) > int(config['Security']['max_request_size']):
                return jsonify({
                    'error': 'Request size too large',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': request.headers.get('X-Request-ID', 'N/A')
                }), HTTPStatus.BAD_REQUEST

            user_ip = hash_sensitive_data(client_ip)
            user_agent = request.headers.get('User-Agent', 'Unknown')
            parsed_ua = user_agent_parser.Parse(user_agent)
            
            tracked_headers = config['Tracking']['track_headers'].split(',')
            headers_data = {header: request.headers.get(header, 'N/A') for header in tracked_headers}
            
            geo_data = await get_geoip_data(client_ip)
            
            client_info = {
                'browser': parsed_ua['user_agent']['family'],
                'browser_version': parsed_ua['user_agent']['major'],
                'os': parsed_ua['os']['family'],
                'os_version': parsed_ua['os']['major'],
                'device': parsed_ua['device']['family'],
                'language': headers_data.get('Accept-Language', 'N/A'),
                'screen_resolution': request.args.get('screen', 'N/A'),
                'referrer': headers_data.get('Referer', 'N/A'),
                'timestamp': datetime.utcnow().isoformat(),
                'request_id': request.headers.get('X-Request-ID', 'N/A'),
                'processing_time': time.time() - start_time
            }
            
            track_data = {
                'ip': user_ip,
                'user_agent': user_agent,
                'original_url': original_url,
                'geo_data': geo_data,
                'client_info': client_info,
                'headers': headers_data,
                'trace_id': trace.get_current_span().get_span_context().trace_id
            }
            
            try:
                redis_key = f"track:{track_data['request_id']}:{int(time.time())}"
                with redis_client.pipeline() as pipe:
                    pipe.setex(redis_key, int(config['Tracking']['retention_days']) * 86400, json.dumps(track_data))
                    pipe.execute()
            except redis.RedisError as e:
                logger.error(f"Redis error: {str(e)}")
            
            async with aiohttp.ClientSession() as session:
                try:
                    with open('tracking.log', 'a') as f:
                        json.dump(track_data, f, ensure_ascii=False)
                        f.write('\n')
                except Exception as e:
                    logger.error(f"Failed to write to tracking log: {str(e)}")
            
            logger.info(f"Redirect tracked: {json.dumps(track_data, ensure_ascii=False)}")
            
            token = jwt.encode(
                {
                    'url': original_url,
                    'ip': user_ip,
                    'ts': datetime.utcnow().isoformat(),
                    'exp': datetime.utcnow() + timedelta(seconds=int(config['Security']['jwt_expiry']))
                },
                config['Server']['jwt_secret'],
                algorithm='HS256'
            )
            
            response = redirect(original_url, code=302)
            response.headers['X-Tracking-Token'] = token
            return response
            
        except Exception as e:
            logger.error(f"Track error: {str(e)}", exc_info=True)
            return jsonify({
                'error': 'Failed to process redirect',
                'timestamp': datetime.utcnow().isoformat(),
                'request_id': request.headers.get('X-Request-ID', 'N/A'),
                'trace_id': trace.get_current_span().get_span_context().trace_id
            }), HTTPStatus.INTERNAL_SERVER_ERROR

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '0.0.0.0'

def parse_args():
    parser = argparse.ArgumentParser(description='Enhanced Flask Redirect Service')
    parser.add_argument('--host', type=str, help='Host to bind to')
    parser.add_argument('--port', type=int, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--workers', type=int, help='Number of worker processes')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    host = args.host if args.host else config['Server']['host']
    if host == 'auto':
        host = get_local_ip()
    
    port = args.port if args.port else int(config['Server']['port'])
    workers = args.workers if args.workers else int(config['Server']['workers'])
    
    ssl_context = None
    if config['Server']['ssl_cert'] and config['Server']['ssl_key']:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(
            certfile=config['Server']['ssl_cert'],
            keyfile=config['Server']['ssl_key']
        )
    
    app.start_time = datetime.now()
    
    logger.info(f"Starting server on {host}:{port} with {workers} workers, SSL: {bool(ssl_context)}")
    
    try:
        from gunicorn.app.base import BaseApplication
        
        class FlaskApplication(BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()
            
            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)
            
            def load(self):
                return self.application
        
        gunicorn_options = {
            'bind': f'{host}:{port}',
            'workers': workers,
            'timeout': int(config['Server']['timeout']),
            'loglevel': 'info',
            'accesslog': '-',
            'errorlog': '-',
            'worker_class': 'gevent',
            'ssl_version': 'TLS' if ssl_context else None,
            'certfile': config['Server']['ssl_cert'] if ssl_context else None,
            'keyfile': config['Server']['ssl_key'] if ssl_context else None,
            'keepalive': 120,
            'max_requests': 1000,
            'max_requests_jitter': 100
        }
        
        FlaskApplication(app, gunicorn_options).run()
        
    except ImportError:
        logger.warning("Gunicorn not available, falling back to Flask's development server")
        app.run(
            host=host,
            port=port,
            debug=args.debug,
            threaded=True,
            processes=1,
            ssl_context=ssl_context
        )