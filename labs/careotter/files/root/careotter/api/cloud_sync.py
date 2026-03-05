#!/usr/bin/env python3
"""
CareOtter Cloud Sync - Secure HTTPS/OAuth2 PKCE client
Syncs cardiac readings to Docker API backend
"""
import asyncio
import json
import logging
import hashlib
import secrets
import urllib.parse
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import ssl

logger = logging.getLogger(__name__)

try:
    import aiohttp
except ImportError:
    aiohttp = None
    logger.warning("[-] aiohttp not installed. Install: pip install aiohttp")


class CloudSync:
    """OAuth2 PKCE + HTTPS client for cloud synchronization"""
    
    def __init__(self, config: Dict, device_id: str, secret_key: Optional[str] = None):
        """
        Args:
            config: Configuration dict with cloud_api settings
            device_id: Unique device identifier (MAC or serial)
            secret_key: Device shared secret (for HMAC signing in vulnerable mode)
        """
        self.config = config
        self.device_id = device_id
        self.secret_key = secret_key
        
        # Cloud API endpoint
        self.api_url = config.get('cloud_api', {}).get('url', 'https://localhost:5000')
        self.verify_ssl = config.get('cloud_api', {}).get('verify_ssl', True)
        
        # OAuth2 PKCE
        self.oauth_enabled = config.get('cloud_api', {}).get('authentication') == 'oauth2_pkce'
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.refresh_token: Optional[str] = None
        
        # Rate limiting & retry
        self.max_retries = config.get('cloud_api', {}).get('max_retries', 3)
        self.retry_delay = config.get('cloud_api', {}).get('retry_delay_seconds', 5)
        self.batch_size = config.get('cloud_api', {}).get('batch_size', 10)
        
        # Self-signed cert handling
        self.tls_version = config.get('cloud_api', {}).get('tls_version', '1.3')
        
    async def authenticate(self, username: str, password: str) -> bool:
        """
        OAuth2 PKCE authentication flow
        SECURE MODE: Uses proper PKCE with code_challenge
        VULNERABLE MODE: Will skip PKCE validation (Phase 2)
        """
        if not self.oauth_enabled:
            logger.warning("[!] OAuth2 disabled in config")
            return False
        
        try:
            # Generate PKCE challenge
            code_verifier = secrets.token_urlsafe(32)  # ~256 bits
            code_challenge = self._generate_code_challenge(code_verifier)
            
            logger.info("[*] Initiating OAuth2 PKCE authentication...")
            
            # Step 1: Get auth code
            auth_code = await self._get_auth_code(code_challenge, username)
            if not auth_code:
                return False
            
            # Step 2: Exchange code for tokens
            tokens = await self._exchange_code_for_tokens(auth_code, code_verifier)
            if not tokens:
                return False
            
            self.access_token = tokens['access_token']
            self.refresh_token = tokens.get('refresh_token')
            
            expires_in = tokens.get('expires_in', 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            logger.info(f"[+] OAuth2 authentication successful. Token expires in {expires_in}s")
            return True
            
        except Exception as e:
            logger.error(f"[-] OAuth2 authentication failed: {e}")
            return False
    
    async def sync_readings(self, readings: List[Dict]) -> bool:
        """
        Upload cardiac readings to cloud
        Implements batching and retries with exponential backoff
        """
        if not readings:
            return True
        
        # Ensure auth token
        if self.oauth_enabled:
            if not self._is_token_valid():
                if not await self._refresh_access_token():
                    logger.error("[-] Failed to refresh OAuth2 token")
                    return False
        
        # Process in batches
        for i in range(0, len(readings), self.batch_size):
            batch = readings[i:i + self.batch_size]
            
            if not await self._upload_batch(batch):
                return False
        
        logger.info(f"[+] Synced {len(readings)} readings to cloud")
        return True
    
    async def sync_alerts(self, alerts: List[Dict]) -> bool:
        """Upload alert data to cloud"""
        if not alerts:
            return True
        
        # Ensure auth
        if self.oauth_enabled and not self._is_token_valid():
            if not await self._refresh_access_token():
                return False
        
        payload = {
            'device_id': self.device_id,
            'alerts': alerts,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return await self._post_with_retry(f'{self.api_url}/alerts', payload)
    
    async def get_device_config(self) -> Optional[Dict]:
        """Fetch updated device configuration from cloud"""
        try:
            if self.oauth_enabled and not self._is_token_valid():
                if not await self._refresh_access_token():
                    return None
            
            response = await self._get_with_retry(f'{self.api_url}/devices/{self.device_id}/config')
            return response
            
        except Exception as e:
            logger.error(f"[-] Failed to fetch device config: {e}")
            return None
    
    # ===== Private Methods =====
    
    def _generate_code_challenge(self, code_verifier: str) -> str:
        """Generate code_challenge from verifier (S256)"""
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = urllib.parse.quote(
            __import__('base64').urlsafe_b64encode(digest).decode().rstrip('='),
            safe=''
        )
        return code_challenge
    
    async def _get_auth_code(self, code_challenge: str, username: str) -> Optional[str]:
        """
        Get authorization code from OAuth2 server
        VULNERABLE MODE: Will skip this in Phase 2 (no PKCE)
        """
        try:
            params = {
                'client_id': self.config.get('cloud_api', {}).get('client_id', 'careotter'),
                'response_type': 'code',
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'redirect_uri': 'http://localhost:8080/callback'
            }
            
            auth_url = f"{self.api_url}/oauth/authorize"
            logger.debug(f"[*] Auth URL: {auth_url}?{urllib.parse.urlencode(params)}")
            
            # In production: would open browser or show QR code
            # For now: simulate manual code entry
            # auth_code = input("Enter authorization code: ")
            # For testing: use hardcoded value
            auth_code = "test_auth_code_123"
            
            return auth_code if auth_code else None
            
        except Exception as e:
            logger.error(f"[-] Failed to get auth code: {e}")
            return None
    
    async def _exchange_code_for_tokens(self, auth_code: str, code_verifier: str) -> Optional[Dict]:
        """Exchange authorization code for access/refresh tokens"""
        try:
            payload = {
                'grant_type': 'authorization_code',
                'code': auth_code,
                'code_verifier': code_verifier,
                'client_id': self.config.get('cloud_api', {}).get('client_id', 'careotter'),
                'client_secret': self.config.get('cloud_api', {}).get('client_secret', ''),
                'redirect_uri': 'http://localhost:8080/callback'
            }
            
            return await self._post_with_retry(f'{self.api_url}/oauth/token', payload, no_auth=True)
            
        except Exception as e:
            logger.error(f"[-] Failed to exchange code: {e}")
            return None
    
    def _is_token_valid(self) -> bool:
        """Check if access token is still valid"""
        if not self.access_token or not self.token_expires_at:
            return False
        
        # Refresh if expiring within 5 minutes
        return datetime.now() < (self.token_expires_at - timedelta(minutes=5))
    
    async def _refresh_access_token(self) -> bool:
        """Refresh OAuth2 access token using refresh_token"""
        if not self.refresh_token:
            logger.warning("[!] No refresh_token available")
            return False
        
        try:
            payload = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
                'client_id': self.config.get('cloud_api', {}).get('client_id', 'careotter')
            }
            
            response = await self._post_with_retry(
                f'{self.api_url}/oauth/token',
                payload,
                no_auth=True
            )
            
            if response:
                self.access_token = response['access_token']
                expires_in = response.get('expires_in', 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
                logger.info("[+] Access token refreshed")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"[-] Token refresh failed: {e}")
            return False
    
    async def _upload_batch(self, batch: List[Dict]) -> bool:
        """Upload a batch of readings"""
        payload = {
            'device_id': self.device_id,
            'readings': batch,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return await self._post_with_retry(f'{self.api_url}/readings', payload)
    
    async def _get_headers(self, no_auth: bool = False) -> Dict[str, str]:
        """Build HTTP headers with auth token"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'CareOtter/1.0'
        }
        
        if not no_auth and self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        
        return headers
    
    async def _post_with_retry(self, url: str, payload: Dict, no_auth: bool = False) -> Optional[Dict]:
        """POST with exponential backoff retry"""
        if not aiohttp:
            logger.error("[-] aiohttp required for cloud sync")
            return None
        
        for attempt in range(self.max_retries):
            try:
                # SSL context for self-signed certs (vulnerable in Phase 2)
                ssl_context = None
                if not self.verify_ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                
                async with aiohttp.ClientSession() as session:
                    headers = await self._get_headers(no_auth)
                    
                    async with session.post(
                        url,
                        json=payload,
                        headers=headers,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status == 401 and not no_auth:
                            logger.warning("[!] Authentication failed, retrying...")
                            continue
                        else:
                            logger.error(f"[-] Server error: {resp.status}")
                            text = await resp.text()
                            logger.debug(f"Response: {text}")
                            
            except asyncio.TimeoutError:
                logger.warning(f"[!] Request timeout (attempt {attempt + 1}/{self.max_retries})")
            except Exception as e:
                logger.error(f"[-] POST request failed: {e}")
            
            # Exponential backoff
            if attempt < self.max_retries - 1:
                delay = self.retry_delay * (2 ** attempt)
                logger.info(f"[*] Retrying in {delay}s...")
                await asyncio.sleep(delay)
        
        return None
    
    async def _get_with_retry(self, url: str) -> Optional[Dict]:
        """GET with retry logic"""
        if not aiohttp:
            logger.error("[-] aiohttp required for cloud sync")
            return None
        
        for attempt in range(self.max_retries):
            try:
                ssl_context = None
                if not self.verify_ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                
                async with aiohttp.ClientSession() as session:
                    headers = await self._get_headers()
                    
                    async with session.get(
                        url,
                        headers=headers,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        else:
                            logger.error(f"[-] Server error: {resp.status}")
                            
            except asyncio.TimeoutError:
                logger.warning(f"[!] Request timeout (attempt {attempt + 1}/{self.max_retries})")
            except Exception as e:
                logger.error(f"[-] GET request failed: {e}")
            
            if attempt < self.max_retries - 1:
                delay = self.retry_delay * (2 ** attempt)
                await asyncio.sleep(delay)
        
        return None
