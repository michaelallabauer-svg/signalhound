import {test,expect,type Page} from '@playwright/test';
const source={id:'node-1',node_id:1,organization_id:1,name:'Branch node',bind_ip:'192.0.2.2',target_scope_ids:[1],allowed_ports:[443]};
const zone={id:1,organization_id:1,name:'Server zone',target:'192.0.2.0/24',target_type:'CIDR',scan_zone:'INTERNAL_IT',active:true};
async function fixture(page:Page,empty=false) {
 let rules:any[]=[];let jobs:any[]=[];let checks:any[]=[];let backendCalls=0;let queued=0;let complete=false;
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/health',r=>r.fulfill({json:{status:'ok'}}));
 await page.route('**/api/v1/**',r=>{
  const path=new URL(r.request().url()).pathname.replace('/api/v1','');const method=r.request().method();
  if(path==='/nodes')return r.fulfill({json:{enabled:!empty,required_version:'1.0.0',nodes:empty?[]:[{...source,id:1,capabilities:['tcp_connect_v1'],reported_capabilities:['tcp_connect_v1'],active:true,online:true,ready:true,version:'1.0.0',last_seen_at:'2026-10-04T12:00:00Z',execution_enabled:true,credential_generation:1}]}});
  if(path==='/nodes/jobs')return r.fulfill({json:jobs});
  if(path==='/segmentation/config')return r.fulfill({json:{enabled:true,node_execution_enabled:true,sources:[source],configuration_error:null,notice:'Node-reported evidence; no zone-wide certification.'}});
  if(path==='/segmentation/rules'){
   if(method==='POST'){const row={...r.request().postDataJSON(),id:1,source,zone,active:true,created_at:'2026-10-04T12:00:00Z'};rules=[row];return r.fulfill({status:201,json:row});}
   if(complete && jobs.length){jobs[0]={...jobs[0],status:'COMPLETED',check_id:1};checks=[{id:1,rule_id:1,status:'FAIL',outcome:'UNEXPECTED_ACCESS',created_at:'2026-10-04T12:00:01Z',expected:{...rules[0],access:'DENY'},observed:{state:'TCP_CONNECTED',attempted:true,detail:'TCP accepted',notice:'Authenticated node report.',node_id:1,node_job_id:1,node_version:'1.0.0',actual_source_ip:'192.0.2.2',duration_ms:1}}];}
   return r.fulfill({json:rules});
  }
  if(path==='/nodes/rules/1/queue'){queued++;const job={id:1,node_id:1,rule_id:1,status:'QUEUED',expected:{...rules[0],access:'DENY'},created_at:'2026-10-04T12:00:00Z',expires_at:'2026-10-04T12:10:00Z',check_id:null,message:null};jobs=[job];return r.fulfill({status:201,json:job});}
  if(path==='/segmentation/rules/1/checks'){if(method==='POST')backendCalls++;return r.fulfill({json:checks});}
  const data:Record<string,unknown>={'/organizations':[{id:1,name:'Node test'}],'/scopes':[zone]};
  return r.fulfill({json:data[path]??[]});
 });
 await page.goto('/');return {errors,backendCalls:()=>backendCalls,queued:()=>queued,complete:()=>{complete=true;}};
}

test('empty node deployment and private credential setup are explained',async({page})=>{
 const state=await fixture(page,true);
 await page.getByRole('button',{name:'Scanner nodes',exact:true}).click();
 const panel=page.getByRole('region',{name:'Distributed scanner nodes'});
 await expect(panel.getByText('No nodes registered on this page.',{exact:false})).toBeVisible();
 await expect(panel.getByText('Distributed execution is disabled on the server.',{exact:false})).toBeVisible();
 await panel.getByText('Administrator setup',{exact:true}).click();
 await expect(panel.getByText('It writes a new private credential file',{exact:false})).toBeVisible();
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 expect(state.errors).toEqual([]);
});

test('remote rules queue only on the selected node; status and measured result stay separate',async({page})=>{
 const state=await fixture(page);
 await page.getByRole('button',{name:'Scanner nodes',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Branch node · Online'})).toBeVisible();
 await page.getByRole('button',{name:'Node 1 status help'}).focus();
 await expect(page.getByRole('tooltip')).toContainText('not proof of correct routing');await page.keyboard.press('Escape');
 await page.getByRole('button',{name:'Segmentation',exact:true}).click();
 const form=page.getByRole('form',{name:'Prepare segmentation rule'});
 await form.getByLabel('Rule name',{exact:true}).fill('Branch deny policy');
 await form.getByLabel('Scanner source',{exact:true}).selectOption('node-1');
 await form.getByLabel('Target zone',{exact:true}).selectOption('1');
 await form.getByLabel('Destination IP',{exact:true}).fill('192.0.2.10');
 await form.getByLabel('TCP port',{exact:true}).selectOption('443');
 await form.getByLabel('Reason for this rule',{exact:true}).fill('Reviewed branch isolation policy');
 await form.getByRole('button',{name:'Prepare rule — no network traffic'}).click();
 const selected=page.getByRole('region',{name:'Selected segmentation rule'});
 await expect(selected.getByRole('button',{name:'Check one TCP endpoint'})).toHaveCount(0);
 await selected.getByRole('button',{name:'Queue check on selected node'}).click();
 await expect(selected.getByText('Job #1 · QUEUED')).toBeVisible();
 await expect(selected.getByText('No results on this page. Untested is not a pass.')).toBeVisible();
 state.complete();await page.getByRole('button',{name:'Refresh rules and configuration'}).click();
 // Refresh history after the mocked remote completion has become visible.
 await page.getByRole('button',{name:'Refresh rules and configuration'}).click();
 await expect(selected.getByText('Job #1 · COMPLETED')).toBeVisible();
 await expect(selected.getByRole('heading',{name:'FAIL · Unexpected access — connection succeeded'})).toBeVisible();
 await expect(selected.getByText('Authenticated report from node #1',{exact:false})).toBeVisible();
 expect(state.queued()).toBe(1);expect(state.backendCalls()).toBe(0);expect(state.errors).toEqual([]);
});
