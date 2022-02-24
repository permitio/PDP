import requests
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError


AUTH0_DOMAIN = "acalla-dev.us.auth0.com"
API_AUDIENCE = f"https://api.acalla.com/v1/"
ALGORITHMS = ["RS256"]
JWK_TOKENS = requests.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json").json()

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)
    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            if not type(self)._verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token."
                )
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    @classmethod
    def _verify_jwt(cls, jwtoken: str) -> bool:
        # is_token_valid: bool = False

        payload = cls._decode_jwt(jwtoken)
        return payload
        # except HTTPException:
        #     payload = None
        # if payload:
        #     is_token_valid = True
        # return is_token_valid

    @classmethod
    def _decode_jwt(cls, jwtoken: str) -> dict:
        rsa_key = cls._get_rsa_key(jwtoken)
        try:
            return jwt.decode(
                jwtoken,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/",
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail="token is expired",
            )
        except jwt.JWTClaimsError:
            raise HTTPException(
                status_code=401,
                detail="incorrect claims, please check the audience and issuer",
            )
        except Exception as e:
            print(e)
            raise HTTPException(
                status_code=401,
                detail="Unable to parse authentication token." + str(e),
            )

    @staticmethod
    def _get_rsa_key(jwtoken: str) -> dict:
        unverified_header = jwt.get_unverified_header(jwtoken)
        for key in JWK_TOKENS["keys"]:
            if key["kid"] == unverified_header["kid"]:
                return {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        raise HTTPException(
            status_code=401,
            detail="Unable to find appropriate key",
        )