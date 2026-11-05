import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir:'./tests/e2e',workers:1,fullyParallel:false,retries:0,timeout:90000,
  expect:{timeout:15000},reporter:'line',
  use:{baseURL:'http://localhost:15173',headless:true,channel:'msedge',ignoreHTTPSErrors:true,
    viewport:{width:1440,height:1000},trace:'retain-on-failure',screenshot:'only-on-failure',
    launchOptions:{args:['--disable-background-networking','--disable-component-update','--disable-sync','--host-resolver-rules=MAP privileged.localhost 127.0.0.1']}},
});
