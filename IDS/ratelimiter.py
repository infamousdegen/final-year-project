import redis
import time

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int, block_time: int,reddisinstance:redis) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_time = block_time
        self.r = reddisinstance
        

    def addToBlocklist(self, ip_address: str) -> None:
        print("Adding to blocklist")
        key = f"blocklist_ip:{ip_address}"
        self.r.setex(key, self.block_time, "blocked")
        print("Added to blocklist")

    def isBlocked(self, ip_address: str) -> bool:
        key = f"blocklist_ip:{ip_address}"
        return self.r.exists(key) == 1

    def removeFromBlocklist(self, ip_address: str) -> None:
        key = f"blocklist_ip:{ip_address}"
        self.r.delete(key)

    def ratelimiting(self, ip_address: str) -> bool:
        # print("inside ratelimiting")
        current_time = int(time.time())
        key = f"request_rate_limit:{ip_address}"
        self.r.zadd(key, {current_time: current_time})
        self.r.zremrangebyscore(key, 0, current_time - self.window_seconds)
        request_count = self.r.zcard(key)
        # print("max request",self.max_requests)
        # print("request count",request_count,self.max_requests)

        if request_count >= self.max_requests:
            self.addToBlocklist(ip_address)
            return True
        
        self.r.expire(key, self.window_seconds)
        return False
