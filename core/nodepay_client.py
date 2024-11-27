import hashlib
import random
import time
import uuid
import warnings
import json
import os

from random_username.generate import generate_username
from tenacity import retry, stop_after_attempt, retry_if_not_exception_type

from core.base_client import BaseClient
from core.models.exceptions import LoginError, TokenError, CloudflareException
from core.utils import logger
from core.utils.person import Person

# Suppress the specific warning
warnings.filterwarnings("ignore", category=UserWarning, message="Curlm alread closed!")


class NodePayClient(BaseClient):
    TOKENS_FILE = 'data/tokens_db.json'

    def __init__(self, email: str = '', password: str = '', proxy: str = '', user_agent: str = ''):
        super().__init__()
        self.email = email
        self.password = password
        self.user_agent = user_agent
        self.proxy = proxy
        self.browser_id = str(uuid.uuid3(uuid.NAMESPACE_DNS, self.proxy or ""))

    @classmethod
    def load_tokens(cls):
        if os.path.exists(cls.TOKENS_FILE):
            try:
                with open(cls.TOKENS_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    @classmethod
    def save_tokens(cls, tokens):
        os.makedirs(os.path.dirname(cls.TOKENS_FILE), exist_ok=True)
        with open(cls.TOKENS_FILE, 'w') as f:
            json.dump(tokens, f)

    @classmethod
    def get_saved_token(cls, email, proxy):
        tokens = cls.load_tokens()
        key = hashlib.md5(f"{email}:{proxy}".encode()).hexdigest()
        return tokens.get(key, {}).get('token'), tokens.get(key, {}).get('uid'), tokens.get(key, {}).get('browser_id')

    @classmethod
    def save_token(cls, email, proxy, uid, token, browser_id):
        tokens = cls.load_tokens()
        key = hashlib.md5(f"{email}:{proxy}".encode()).hexdigest()
        tokens[key] = {'uid': uid, 'email': email, 'proxy': proxy, 'browser_id': browser_id, 'token': token}
        cls.save_tokens(tokens)

    async def validate_token(self, token):
        try:
            # Try to use the token to get info - if it fails, token is invalid
            await self.info(token)
            return True
        except CloudflareException as e:
            raise CloudflareException(e)
        except Exception:
            return False

    async def __aenter__(self):
        await self.create_session(self.proxy, self.user_agent)
        return self

    async def safe_close(self):
        await self.close_session()

    def _noauth_headers(self):
        return {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://app.nodepay.ai',
            'priority': 'u=1, i',
            'referer': 'https://app.nodepay.ai/',
            'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not?A_Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'none',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'user-agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
    
    def _authed_headers(self, access_token: str):
        headers = self._noauth_headers()
        headers.update({"authorization": f"Bearer {access_token}"})
        return headers

    def _ping_headers(self, access_token: str):
        headers = self._authed_headers(access_token)
        headers.update({"origin": "chrome-extension://lgmpfmgeabnnlemejacfljbmonaomfmm"})
        headers.pop("referer")
        return headers
    

    async def register(self, ref_code: str, captcha_service):
        captcha_token = await captcha_service.get_captcha_token_async()
        username = (generate_username()[0] + Person.random_string_old(random.randint(1, 5)) +
                    str(random.randint(1, 999)))[:20]
        json_data = {
            'email': self.email,
            'password': self.password,
            'username': username,
            'referral_code': ref_code,
            'recaptcha_token': captcha_token
        }

        return await self.make_request(
            method='POST',
            url='https://api.nodepay.org/api/auth/register?',
            headers=self._noauth_headers(),
            json_data=json_data
        )

    @retry(
        stop=stop_after_attempt(5),
        retry=retry_if_not_exception_type(LoginError),
        reraise=True,
        # before_sleep=lambda retry_state, **kwargs: logger.info(f"{retry_state.outcome.exception()}"),
    )
    async def login(self, captcha_service):
        captcha_token = await captcha_service.get_captcha_token_async()
        headers = self._noauth_headers()

        json_data = {
            'user': self.email,
            'password': self.password,
            'remember_me': True,
            'recaptcha_token': captcha_token
        }

        response = await self.make_request(
            method='POST',
            url='https://api.nodepay.org/api/auth/login?',
            headers=headers,
            json_data=json_data
        )

        if not response.get("success"):
            msg = response.get("msg")
            # if response.get("code") == -102:
            #     raise LoginError(msg)

            raise LoginError(msg)

        return response['data']['user_info']['uid'], response['data']['token']

    async def activate(self, access_token: str):
        json_data = {}
        return await self.make_request(
            method='POST',
            url='https://api.nodepay.org/api/auth/active-account?',
            headers=self._ping_headers(access_token),
            json_data=json_data
        )

    async def info(self, access_token: str):
        response = await self.make_request(
            method='GET',
            url='https://api.nodepay.org/api/earn/info?',
            headers=self._authed_headers(access_token)
        )
        return response['data'].get('total_earning', 0)

    async def get_auth_token(self, captcha_service):
        saved_token, saved_uid, saved_browser_id = self.get_saved_token(self.email, self.proxy)
        
        if saved_token:
            logger.info(f"HitCache email={self.email} proxy={self.proxy} uid={saved_uid} browser_id={saved_browser_id} token={saved_token}")
            if await self.validate_token(saved_token):
                return saved_uid, saved_token, saved_browser_id

        uid, token = await self.login(captcha_service)
        self.browser_id = str(uuid.uuid4())
        self.save_token(self.email, self.proxy, uid, token, self.browser_id)
        return uid, token, self.browser_id

    async def ping(self, uid: str, access_token: str):
        json_data = {
            'id': uid,
            'browser_id': self.browser_id,
            'timestamp': int(time.time()),
            'version': '2.2.7'
        }

        try:
            await self.make_request(
                method='POST',
                url='https://nw.nodepay.org/api/network/ping',
                headers=self._ping_headers(access_token),
                json_data=json_data
            )
            
            return await self.info(access_token)
        except Exception as e:
            tokens = self.load_tokens()
            if self.email in tokens:
                del tokens[self.email]
                self.save_tokens(tokens)
            raise TokenError("Token invalid or expired") from e
