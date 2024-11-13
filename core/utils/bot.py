# bot.py
import asyncio
import traceback
from typing import List
from core.utils import logger
import random
from core.utils import proxy_manager
from core.utils.account_manager import AccountManager
from core.utils.file_manager import file_to_list
from core.utils.proxy_manager import load_proxy


class Bot:
    def __init__(self, account_path, proxy_path, threads, ref_codes, captcha_service, delay_range):
        self.threads = threads
        self.ref_codes = ref_codes
        self.captcha_service = captcha_service
        self.account_manager = AccountManager(threads, ref_codes, captcha_service)
        self.should_stop = False
        
        # 直接读取账号信息，包含代理
        self.accounts = file_to_list(account_path)
        logger.success(f'Found {len(self.accounts)} accounts')
        self.delay_range = delay_range
        self.running_tasks = []

    async def process_account(self, account):
        # 解析账号信息
        parts = account.split(',', 1)
        account_info = parts[0]
        proxy_str = parts[1].strip() if len(parts) > 1 else None
        email, password = account_info.split(':', 1)

        while not self.should_stop:
            result = await self.account_manager.mining_loop(email, password, proxy_str)
            if result is True:
                # logger.info(f"Account {email} completed mining cycle. Waiting 50 minutes.")
                await asyncio.sleep(60 * 50)  # Wait 50 minutes
            elif result == "exit":
                logger.info(f"{email} | Stop account due to login error")
                break
            else:
                logger.warning(f"{email} | Mining failed. Retrying in 5 minutes. | {traceback.format_exc()}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def start_mining(self):
        logger.info("Starting mining loop with slow start...")
        pending_accounts = self.accounts.copy()
        
        while pending_accounts and not self.should_stop:
            # Start up to 'threads' number of accounts
            current_batch = []
            while len(current_batch) < self.threads and pending_accounts:
                account = pending_accounts.pop(0)
                email = account.split(':', 1)[0]
                delay = random.uniform(*self.delay_range)
                logger.info(f"{email} | waiting {delay:.2f} sec")
                await asyncio.sleep(delay)
                
                task = asyncio.create_task(self.process_account(account))
                current_batch.append(task)
                self.running_tasks.append(task)
                
            if current_batch:
                # Wait for the current batch to get past initial setup
                await asyncio.sleep(2)
        
        try:
            # Wait for all tasks to complete
            if self.running_tasks:
                await asyncio.gather(*self.running_tasks)
        except asyncio.CancelledError:
            pass
            # logger.info("Mining tasks cancelled")
        finally:
            for task in self.running_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self.running_tasks, return_exceptions=True)
            logger.warning("All mining tasks completed or cleaned up")

    def stop(self):
        logger.info("Stopping Bot")
        self.should_stop = True
        self.account_manager.stop()
        for task in self.running_tasks:
            if not task.done():
                task.cancel()

    async def start_registration(self):
        logger.info("Starting registration with slow start...")
        pending_accounts = self.accounts.copy()
        
        while pending_accounts and not self.should_stop:
            current_batch = []
            while len(current_batch) < self.threads and pending_accounts:
                account = pending_accounts.pop(0)
                email, password = account.split(':', 1)
                delay = random.uniform(*self.delay_range)
                logger.info(f"{email} | waiting {delay:.2f} sec")
                await asyncio.sleep(delay)
                
                task = asyncio.create_task(self.account_manager.register_account(email, password))
                current_batch.append(task)
            
            if current_batch:
                await asyncio.gather(*current_batch)
                await asyncio.sleep(1)  # Small delay between batches
        
        logger.info("Registration process completed")

