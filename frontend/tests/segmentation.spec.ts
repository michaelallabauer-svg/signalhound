import { test, expect, type Page } from '@playwright/test';

const source={id:'lab',organization_id:1,name:'Authorized lab',bind_ip:'192.0.2.2',target_scope_ids:[1],allowed_ports:[443]};
const zone={id:1,organization_id:1,name:'Server zone',target:'192.0.2.0/24',target_type:'CIDR',scan_zone:'INTERNAL_IT',active:true};
async function fixture(page:Page, enabled=true, configured=true) {
  let rules:any[]=[];
  let checks:any[]=[];
  let executions=0;
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/health',r=>r.fulfill({json:{status:'ok'}}));
  await page.route('**/api/v1/**',route=>{
    const path=new URL(route.request().url()).pathname.replace('/api/v1','');
    const method=route.request().method();
    if(path==='/segmentation/config') return route.fulfill({json:{enabled,sources:configured?[source]:[],configuration_error:null,notice:'TCP checks are not proof of zone isolation.',cooldown_seconds:5}});
    if(path==='/segmentation/rules') {
      if(method==='POST') {
        const payload=route.request().postDataJSON();
        expect(payload.organization_id).toBe(1);
        const row={...payload,id:1,source,zone,active:true,created_at:'2026-10-04T10:00:00Z'};
        rules=[row]; return route.fulfill({status:201,json:row});
      }
      return route.fulfill({json:rules});
    }
    if(path==='/segmentation/rules/1/archive') {
      rules[0]={...rules[0],active:false};return route.fulfill({json:rules[0]});
    }
    if(path==='/segmentation/rules/1/checks') {
      if(method==='POST') {
        executions++;
        const check={id:executions,rule_id:1,created_at:'2026-10-04T10:00:10Z',status:executions===1?'FAIL':'ERROR',outcome:executions===1?'UNEXPECTED_ACCESS':'ERROR',
          expected:{name:rules[0].name,source,zone,target:rules[0].target,port:443,access:'DENY',rationale:rules[0].rationale,policy_version:'segmentation-tcp-v1'},
          observed:{state:executions===1?'TCP_CONNECTED':'TIMEOUT',attempted:true,detail:executions===1?'TCP connection accepted.':'No conclusive response; not proof of isolation.',actual_source_ip:source.bind_ip,duration_ms:10,notice:'No zone-wide safety score.'}};
        checks=[check,...checks];return route.fulfill({status:201,json:check});
      }
      return route.fulfill({json:checks});
    }
    const data:Record<string,unknown>={'/organizations':[{id:1,name:'Segmentation test'}],'/scopes':[zone]};
    return route.fulfill({json:data[path]??[]});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'Segmentation',exact:true}).click();
  await expect(page.getByRole('region',{name:'Network segmentation',exact:true})).toBeVisible();
  await expect(page.getByText('Loading authorized configuration…')).toHaveCount(0);
  return {errors,executions:()=>executions};
}
async function prepare(page:Page) {
  const form=page.getByRole('form',{name:'Prepare segmentation rule'});
  await form.getByLabel('Rule name',{exact:true}).fill('Guest to server <script>alert(1)</script>');
  await form.getByLabel('Scanner source',{exact:true}).selectOption('lab');
  await form.getByLabel('Target zone',{exact:true}).selectOption('1');
  await form.getByLabel('Destination IP',{exact:true}).fill('192.0.2.10');
  await form.getByLabel('TCP port',{exact:true}).selectOption('443');
  await form.getByLabel('Reason for this rule',{exact:true}).fill('Approved guest boundary must deny web access.');
  await form.getByRole('button',{name:'Prepare rule — no network traffic'}).click();
  await expect(page.getByRole('region',{name:'Selected segmentation rule'})).toBeVisible();
}

test('disabled deployment explains setup without invented source or results',async({page})=>{
  const state=await fixture(page,false,false);
  await expect(page.getByText('No authorized scanner source is configured', {exact:false})).toBeVisible();
  await expect(page.getByRole('button',{name:'Prepare rule — no network traffic'})).toBeDisabled();
  await page.getByText('Administrator setup and source limitations',{exact:true}).click();
  await expect(page.getByText('Docker Desktop is not automatically', {exact:false})).toBeVisible();
  expect(state.executions()).toBe(0);expect(state.errors).toEqual([]);
});

test('prepare, execute, evidence history, accessible help and archive',async({page})=>{
  const state=await fixture(page);
  await prepare(page);
  expect(state.executions()).toBe(0);
  const selected=page.getByRole('region',{name:'Selected segmentation rule'});
  await expect(selected.getByText('No results on this page. Untested is not a pass.')).toBeVisible();
  await page.getByRole('button',{name:'Result interpretation help'}).focus();
  await expect(page.getByRole('tooltip')).toContainText('ERROR is inconclusive');
  await page.keyboard.press('Escape');await expect(page.getByRole('tooltip')).toHaveCount(0);
  await selected.getByRole('button',{name:'Check one TCP endpoint'}).click();
  await expect(selected.getByRole('heading',{name:'FAIL · Unexpected access — connection succeeded'})).toBeVisible();
  await expect(selected.getByText('Bound source: 192.0.2.2 · 10 ms')).toBeVisible();
  await selected.getByRole('button',{name:'Check one TCP endpoint'}).click();
  await expect(selected.getByRole('heading',{name:'ERROR · Inconclusive — review evidence'})).toBeVisible();
  await expect(selected.getByRole('heading',{name:'FAIL · Unexpected access — connection succeeded'})).toBeVisible();
  await selected.getByRole('button',{name:'Archive rule',exact:true}).click();
  await expect(selected.getByRole('button',{name:'Check one TCP endpoint'})).toBeDisabled();
  await expect(selected.getByText('Archived rules cannot run checks.')).toBeVisible();
  await page.setViewportSize({width:390,height:844});
  await expect(selected.getByRole('heading',{name:'ERROR · Inconclusive — review evidence'})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  expect(state.executions()).toBe(2);expect(state.errors).toEqual([]);
});

test('configured but disabled execution can prepare without starting traffic',async({page})=>{
  const state=await fixture(page,false,true);
  await prepare(page);
  await expect(page.getByRole('button',{name:'Check one TCP endpoint'})).toBeDisabled();
  await expect(page.getByText('Execution is disabled.',{exact:false})).toBeVisible();
  expect(state.executions()).toBe(0);expect(state.errors).toEqual([]);
});
