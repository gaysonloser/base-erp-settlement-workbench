const fail=(state,reason,extra={})=>({schema_version:'base-erp-h212-platform-feasibility-v1',state,reason,receipt_eligible:false,publication_unit:0,...extra});
export const CANONICAL_APP_ID='6a7a0717e209a55163497d2d';
export const CANONICAL_PRIMARY_URL='https://base-erp-settlement-workbench.onrender.com';
export function evaluatePlatformEvidence({platform,app_id,primary_url,owner_verified=false,metadata={},native_release_fields=false,target='' }={}) {
  const t=String(target||'').toLowerCase(); if(t.includes('circle')||t.includes('arc')) return fail('owner_platform_gate_no_overwrite','base_circle_identity_collision');
  if(platform==='base.dev'||platform==='base_dashboard') {
    if(app_id===CANONICAL_APP_ID&&primary_url===CANONICAL_PRIMARY_URL&&owner_verified) return {schema_version:'base-erp-h212-platform-feasibility-v1',state:'canonical_route_verified',receipt_eligible:false,publication_unit:0,canonical_app_id:app_id,canonical_primary_url:primary_url,release_fields_native:false};
    return fail('owner_platform_gate','canonical_app_identity_unverified');
  }
  if(platform==='base_app') { const keys=['name','icon','tagline','description','screenshots','category','builder_code']; return keys.every(k=>metadata[k])&&app_id===CANONICAL_APP_ID ? {schema_version:'base-erp-h212-platform-feasibility-v1',state:'base_app_readiness',receipt_eligible:false,publication_unit:0,canonical_app_id:app_id} : fail('base_app_readiness_required','no_independent_release_receipt'); }
  if(platform==='talent') return fail('talent_platform_gate','reputation_or_profile_observation_only');
  if(platform==='guild') return fail('guild_platform_gate','community_object_not_release');
  if(platform==='basename_base_org') return fail('basename_wallet_gate','identity_receipt_not_release');
  if(native_release_fields===false) return fail('platform_gate','missing_native_release_fields');
  return fail('owner_platform_gate','unsupported_platform');
}
export function collapseAlias(evidence=[]) { const valid=evidence.filter(x=>x.state==='canonical_route_verified'); return valid.length?{canonical:true,app_id:valid[0].canonical_app_id,primary_url:valid[0].canonical_primary_url,duplicate_receipts:0}:{canonical:false,duplicate_receipts:0}; }
