from better_proxy import Proxy

def parse_proxy(proxy_str: str) -> str:
    """将代理字符串转换为URL格式"""
    if not proxy_str:
        return None
    return Proxy.from_str(proxy_str).as_url
