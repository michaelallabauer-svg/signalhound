import { test, expect, type Page } from '@playwright/test';
import { emptyContext } from './fixtures';

async function fixture(page: Page, conflict = false) {
  let context: any = { ...emptyContext };
  let history: any[] = [];
  let sites: any[] = [];
  let snapshots: any[] = [];
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/health', r => r.fulfill({ json: { status:'ok' } }));
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1','');
    const method = route.request().method();
    if (path === '/assets/1/context') {
      if(method === 'PATCH') {
        if(conflict) return route.fulfill({status:409,json:{detail:'Asset context changed elsewhere. Reload the current context before saving again.'}});
        const { organization_id, expected_revision, ...payload } = route.request().postDataJSON();
        expect(expected_revision).toBe(context.revision);
        const before = context;
        context = { ...context,...payload, organization_id, revision:context.revision+1,
          updated_at:'2026-10-03T12:00:00Z', site:sites.find(s=>s.id===payload.site_id)??null };
        history=[{id:context.revision,asset_id:1,revision:context.revision,changed_at:context.updated_at,before,after:context},...history];
      }
      return route.fulfill({json:context});
    }
    if(path==='/assets/1/context/history') return route.fulfill({json:history});
    if(path==='/sites') {
      if(method==='POST') {
        const created={...route.request().postDataJSON(),id:sites.length+1,active:true,revision:1,created_at:'2026-10-03',updated_at:'2026-10-03'};
        sites.push(created); return route.fulfill({status:201,json:created});
      }
      return route.fulfill({json:sites});
    }
    if(path==='/sites/1' && method==='PATCH') {
      sites[0]={...sites[0],...route.request().postDataJSON(),revision:sites[0].revision+1};
      if(context.site_id===1) context={...context,site:sites[0]};
      return route.fulfill({json:sites[0]});
    }
    if(path==='/assets/1/risk') {
      if(method==='POST') {
        const payload=route.request().postDataJSON();
        expect(payload.criticality).toBeNull();
        const saved={id:1,asset_id:1,created_at:'2026-10-03',algorithm_version:'exposure-v1.0',
          context:{...payload,criticality:context.criticality??'UNKNOWN',criticality_source:'asset_context',business_context:context},
          result:{status:'NO_EVIDENCE',lower:null,upper:null,entries:[],excluded:[],warnings:[],notice:'No evidence does not mean safe.',aggregation:'Maximum'}};
        snapshots=[saved]; return route.fulfill({status:201,json:saved});
      }
      return route.fulfill({json:{algorithm_version:'exposure-v1.0',snapshots}});
    }
    const asset={id:1,organization_id:1,value:'192.0.2.1',asset_type:'IP',active:true,source:'nmap',first_seen:'2026-10-03',last_seen:'2026-10-03'};
    const data:Record<string,unknown>={ '/organizations':[{id:1,name:'Context test'}],'/assets':[asset],
      '/assets/1/detail':{...asset,services:[],observations:[],service_observations:[],findings:[]},
      '/assets/1/intelligence':{enabled:false,inputs:[],software:[],runs:[]} };
    return route.fulfill({json:data[path]??[]});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'Inventory',exact:true}).click();
  await expect(page.getByRole('region',{name:'Asset business context'})).toBeVisible();
  return { errors };
}

test('persistent business fields, location lifecycle, history and risk inheritance', async ({page})=>{
  const state=await fixture(page);
  const region=page.getByRole('region',{name:'Asset business context'});
  await region.getByRole('combobox',{name:'Business criticality',exact:true}).selectOption('HIGH');
  await region.getByRole('combobox',{name:'Environment',exact:true}).selectOption('PRODUCTION');
  await region.getByRole('textbox',{name:'Technical owner',exact:true}).fill('<img src=x onerror=alert(1)>');
  await region.getByRole('textbox',{name:'Business owner',exact:true}).fill('Service owner');
  await region.getByRole('textbox',{name:'Responsible team',exact:true}).fill('Infrastructure');
  await region.getByText('Manage organization locations',{exact:true}).click();
  await region.getByLabel('New location name').fill('Vienna office');
  await region.getByRole('button',{name:'Create location',exact:true}).click();
  await expect(region.getByRole('option',{name:'Vienna office',exact:true})).toBeAttached();
  await region.getByRole('combobox',{name:'Location',exact:true}).selectOption('1');
  await region.getByRole('button',{name:'Save business context',exact:true}).click();
  await expect(region).toContainText('Business context saved (revision 1)');
  await region.getByText('Business context change history',{exact:true}).click();
  await expect(region).toContainText('Unassigned → HIGH');
  await expect(region.locator('img')).toHaveCount(0);
  const risk=page.getByRole('region',{name:'Exposure and risk'});
  await expect(risk.getByRole('option',{name:'Use saved asset value (HIGH)'})).toBeAttached();
  await risk.getByRole('button',{name:'Calculate priority',exact:true}).click();
  await expect(risk).toContainText('revision 1 · PRODUCTION · Vienna office');
  await region.getByText('Vienna office · Active',{exact:true}).click();
  await region.getByRole('button',{name:'Archive location',exact:true}).click();
  await expect(region.getByRole('option',{name:'Vienna office (archived)'})).toBeAttached();
  await region.getByText('Vienna office · Archived',{exact:true}).click();
  await region.getByRole('button',{name:'Restore location',exact:true}).click();
  await expect(region.getByRole('option',{name:'Vienna office',exact:true})).toBeAttached();
  await page.reload();
  await page.getByRole('button',{name:'Inventory',exact:true}).click();
  await expect(region.getByRole('textbox',{name:'Responsible team',exact:true})).toHaveValue('Infrastructure');
  expect(state.errors).toEqual([]);
});

test('conflict retains draft; reload explicitly discards it; mobile keyboard help',async ({page})=>{
  await page.setViewportSize({width:390,height:844});
  const state=await fixture(page,true);
  const region=page.getByRole('region',{name:'Asset business context'});
  await region.getByRole('textbox',{name:'Technical owner',exact:true}).fill('Unsaved owner');
  await region.getByRole('button',{name:'Save business context',exact:true}).click();
  await expect(region.getByRole('alert')).toContainText('changed elsewhere');
  await expect(region.getByRole('textbox',{name:'Technical owner',exact:true})).toHaveValue('Unsaved owner');
  await region.getByRole('button',{name:'Help for business criticality'}).focus();
  await expect(page.getByRole('tooltip')).toContainText('New priority calculations');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);
  await region.getByRole('button',{name:'Reload saved context (discard edits)'}).click();
  await expect(region.getByRole('textbox',{name:'Technical owner',exact:true})).toHaveValue('');
  expect(state.errors).toEqual([]);
});
