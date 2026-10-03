import { emptyContext } from './fixtures';
import { test, expect, type Page } from '@playwright/test';
const snapshot = {
  id: 1, asset_id: 1, algorithm_version: 'exposure-v1.0', created_at: '2026-10-03T12:00:00Z',
  context: { exposure:'UNKNOWN', criticality:'UNKNOWN', rationale:'', asset_active:true },
  result: { status:'INCOMPLETE', lower:15, upper:90, notice:'Heuristic priority, not breach probability.', aggregation:'Maximum across entries, never sum.',
    warnings:['Intelligence #1 is PARTIAL; coverage may be incomplete.'], excluded:[{finding_id:9,status:'RESOLVED'}],
    entries:[{key:'finding:1',title:'<img src=x onerror=alert(1)>',kind:'FINDING',finding_id:1,finding_status:'ACCEPTED_RISK',
      intelligence_run_id:1,cve_id:'CVE-2021-44228',status:'INCOMPLETE',band:'UNCERTAIN',lower:15,upper:90,base_lower:30,base_upper:90,
      components:[{name:'cvss',raw:10,known:true,lower:30,upper:30,weight:30,source:'Intelligence #1 / NVD'},
        {name:'confidence',raw:null,known:false,lower:.5,upper:1,weight:null,operation:'multiply',source:'No fresh confidence'}]}]
  }
};
async function setup(page: Page, empty = false) {
  let snapshots: unknown[] = [];
  let posts = 0;
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/health', r => r.fulfill({json:{status:'ok'}}));
  await page.route('**/api/v1/**', route => {
    const path=new URL(route.request().url()).pathname.replace('/api/v1','');
    if(path==='/assets/1/risk') {
      if(route.request().method()==='POST') {
        posts++;
        const payload=route.request().postDataJSON();
        expect(payload.organization_id).toBe(1);
        const result=empty ? {...snapshot.result,status:'NO_EVIDENCE',lower:null,upper:null,entries:[]} : snapshot.result;
        const saved={...snapshot,context:payload,result};
        snapshots=[saved];
        return route.fulfill({status:201,json:saved});
      }
      return route.fulfill({json:{algorithm_version:'exposure-v1.0',snapshots}});
    }
    const asset={id:1,organization_id:1,value:'192.0.2.1',asset_type:'IP',active:true,source:'nmap',first_seen:'2026-10-03',last_seen:'2026-10-03'};
    const data:Record<string,unknown>={
      '/assets/1/context': emptyContext, '/assets/1/context/history': [],
      '/organizations':[{id:1,name:'Risk test'}],'/assets':[asset],
      '/assets/1/detail':{...asset,services:[],observations:[],service_observations:[],findings:[]},
      '/assets/1/intelligence':{enabled:false,inputs:[],software:[],runs:[]}
    };
    return route.fulfill({json:data[path]??[]});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'Inventory',exact:true}).click();
  await expect(page.getByRole('region',{name:'Exposure and risk'})).toBeVisible();
  return {posts:()=>posts,errors};
}

test('explicit calculation, no implicit confirmation, ledger and keyboard help', async ({page})=>{
  const state=await setup(page);
  expect(state.posts()).toBe(0);
  await page.getByRole('button',{name:'Calculate priority',exact:true}).click();
  const region=page.getByRole('region',{name:'Exposure and risk'});
  await expect(region).toContainText('15–90 / 100');
  await expect(region).toContainText('exposure-v1.0');
  await expect(region).toContainText('Finding #9 (RESOLVED)');
  const issue=region.locator('.intelligence-candidate');
  await issue.locator('summary').click();
  await expect(issue).toContainText('ACCEPTED_RISK');
  await expect(issue).toContainText('<img src=x onerror=alert(1)>');
  await expect(issue.locator('img')).toHaveCount(0);
  await expect(issue.getByRole('list',{name:'Score components'})).toBeVisible();
  await page.getByRole('button',{name:'Explain confidence for finding:1'}).focus();
  await expect(page.getByRole('tooltip')).toContainText('not whether exploitation was confirmed');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);
  expect(state.errors).toEqual([]);
});

test('context requires rationale; absent evidence is not zero risk on mobile', async ({page})=>{
  await page.setViewportSize({width:390,height:844});
  const state=await setup(page,true);
  const region=page.getByRole('region',{name:'Exposure and risk'});
  await region.locator('select').first().selectOption('INTERNET');
  await expect(page.getByRole('button',{name:'Calculate priority',exact:true})).toBeDisabled();
  await region.locator('textarea').fill('Verified internet-facing service');
  await page.getByRole('button',{name:'Calculate priority',exact:true}).click();
  await expect(region).toContainText('Not scored');
  await expect(region).toContainText('This is not a zero-risk or safe result');
  await expect(region).toContainText('Verified internet-facing service');
  await page.getByRole('button',{name:'About priority range 1'}).click();
  await expect(page.getByRole('tooltip')).toContainText('not a statistical confidence interval');
  expect(state.posts()).toBe(1);
  expect(state.errors).toEqual([]);
});
