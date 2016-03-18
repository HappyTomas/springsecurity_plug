package com.kalian.security.plug.authority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;

import com.kalian.security.plug.authority.base.SystemConstants;
import com.kalian.security.provide.service.SecurityResponse;
import com.kalian.security.provide.service.dto.PlatformAuthorityResourceDTO;
import com.kalian.security.provide.service.dto.PlatformRoleDTO;
import com.kalian.security.provide.service.share.SecurityPlatformAuthorityResourceService;
import com.kalian.security.provide.service.share.SecurityPlatformRoleService;

@Component
public class UserSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	private static Logger log = Logger.getLogger(UserSecurityMetadataSource.class);
	
	private static Map<String, String> resource_url_map = null;
	
	private static List<PlatformAuthorityResourceDTO> platformAuthorityResource_list = new ArrayList<>();
	
	private static Map<String, String> menu_url_map = null;
	
	@Resource
	private SecurityPlatformAuthorityResourceService securityPlatformAuthorityResourceService;
	
	@Resource
	private SecurityPlatformRoleService securityPlatformRoleService;
	
	private static Collection<ConfigAttribute> ABSOLUTE_SECURITY_CONFIGATTRIBUTES;
	
	static{
		ABSOLUTE_SECURITY_CONFIGATTRIBUTES = new ArrayList<>();
		ABSOLUTE_SECURITY_CONFIGATTRIBUTES.add(new SecurityConfig("ABSOLUTE_SECURITY_" + new Random().nextFloat()));
	}
	
	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		
		PlatformAuthorityResourceDTO platformAuthorityResource = new PlatformAuthorityResourceDTO();
		
		platformAuthorityResource.setPar_platform(SystemConstants.PLATFORM_CODE);
		platformAuthorityResource.setPar_dr(SystemConstants.DELETE_NO);
		platformAuthorityResource.setPar_status(SystemConstants.AUTHORITYRESOURCE_STATUS_ENABLE);
		
		try {
			SecurityResponse<PlatformAuthorityResourceDTO> securityResp = securityPlatformAuthorityResourceService.loadAuthorityResource(platformAuthorityResource);
			platformAuthorityResource_list = securityResp.getData();
		} catch (Exception e) {
			log.error("获取平台权限资源发生异常", e);
			System.exit(0);
		}
		
		resource_url_map = new HashMap<>();
		menu_url_map = new HashMap<>();
		
		String par_check_code;
		for(PlatformAuthorityResourceDTO p : platformAuthorityResource_list){
			par_check_code = p.getPar_check_code().toUpperCase();
			resource_url_map.put(par_check_code, p.getPar_id());
			if(p.getPar_level() == 3){
				menu_url_map.put(par_check_code, p.getPar_id());
			}
		}
		
		return ABSOLUTE_SECURITY_CONFIGATTRIBUTES;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object paramObject) throws IllegalArgumentException {
		
		Collection<ConfigAttribute> configAttributeLt = new ArrayList<>();
		
		String url = ((FilterInvocation)paramObject).getRequestUrl();
		String checkCode = getCheckCode(url).toUpperCase();
		
		
		log.debug("用户请求的URL地址：" + url + ", 权限验证标识：" + checkCode);
		
		//获取访问该地址所需的权限
		String par_id = resource_url_map.get(checkCode);
		Map<String, Object> paramMap = new HashMap<>();
		paramMap.put("pr_platform", SystemConstants.PLATFORM_CODE);
		paramMap.put("par_id",par_id );
		if(par_id != null){
			try {
				SecurityResponse<PlatformRoleDTO> respo = securityPlatformRoleService.loadRoleByAuthorityResourceId(paramMap);
				
				List<PlatformRoleDTO> platformRoleLt = respo.getData();
				
				for(PlatformRoleDTO platformRole : platformRoleLt){
					configAttributeLt.add(new SecurityConfig(platformRole.getPr_name()));
				}
				
				return configAttributeLt;
			} catch (Exception e) {
				log.error("获取资源可用的角色发生异常", e);
			}
		}
		
		
		return ABSOLUTE_SECURITY_CONFIGATTRIBUTES;
	}

	@Override
	public boolean supports(Class<?> paramClass) {
		// TODO Auto-generated method stub
		return true;
	}
	
	public String getCheckCode(String url) {
		String checkCode;
		
		url = url.replaceAll("[?]", "/");
		
		String[] ss = url.split("/");
		
		if(ss.length < 4){
			checkCode = url;
		}else{
			checkCode = "/" + ss[1] + "/" + ss[2] + "/" + ss[3];			
		}
		
		return checkCode;
	}
	
	public String getMenuId(String url){
		return menu_url_map.get(url);
	}
}
