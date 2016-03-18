package com.kalian.security.plug.authority;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.kalian.security.plug.authority.base.SystemConstants;
import com.kalian.security.provide.service.SecurityResponse;
import com.kalian.security.provide.service.dto.MenuDTO;
import com.kalian.security.provide.service.dto.PlatformRoleDTO;
import com.kalian.security.provide.service.dto.PlatformUserBaseDTO;
import com.kalian.security.provide.service.share.SecurityPlatformAuthorityResourceService;
import com.kalian.security.provide.service.share.SecurityPlatformRoleService;
import com.kalian.security.provide.service.share.SecurityPlatformUserBaseService;

@Component
public class UserDetailsServiceImpl implements UserDetailsService {

	private Logger log = Logger.getLogger(UserDetailsServiceImpl.class);

	@Resource
	private SecurityPlatformAuthorityResourceService securityPlatformAuthorityResourceService;
	
	@Resource
	private SecurityPlatformUserBaseService securityPlatformUserBaseService;
	
	@Resource
	private SecurityPlatformRoleService securityPlatformRoleService;
	
	
	/**
	 * 根据Cas返回的登录用户名，为用户信息设置其拥有的相应权限，及其可见菜单
	 */
	@Override
	public UserDetails loadUserByUsername(String login_name) throws UsernameNotFoundException {
		LoginUserDetails loginUserDetails = new LoginUserDetails();
		
		
		try {
			PlatformUserBaseDTO platformUserBaseDto = new PlatformUserBaseDTO();
			
			platformUserBaseDto.setPub_login_name(login_name);
			platformUserBaseDto.setPub_dr(SystemConstants.DELETE_NO);
			platformUserBaseDto.setPub_status(SystemConstants.AUTHORITYRESOURCE_STATUS_ENABLE);
			platformUserBaseDto.setPub_orgid(SystemConstants.GLOBAL_ORG_ID);
			
			// 获取用户信息
			SecurityResponse<PlatformUserBaseDTO> securityRespo = 
					securityPlatformUserBaseService.loginUserCheck(platformUserBaseDto,SystemConstants.PLATFORM_CODE);
			List<PlatformUserBaseDTO> listDto = securityRespo.getData();
			if(listDto.size() == 0 || listDto.get(0) == null){
				throw new UsernameNotFoundException("未找到用户信息");
			}
			PlatformUserBaseDTO platformUserBase = listDto.get(0);
			
			loginUserDetails.setUser_id(platformUserBase.getPub_id());
			loginUserDetails.setUsername(login_name);
			loginUserDetails.setPassword(platformUserBase.getPub_login_pwd());
			loginUserDetails.setRegisterdate(platformUserBase.getPub_add_date());
			Map<String, Object> paramMap = new HashMap<>();
			paramMap.put("pub_id", platformUserBase.getPub_id());
			paramMap.put("pr_platform",SystemConstants.PLATFORM_CODE);
			paramMap.put("pr_status", SystemConstants.ROLE_STATUS_ENABLE);
			paramMap.put("pr_dr", SystemConstants.DELETE_NO);
			
			// 获取用户角色
			SecurityResponse<PlatformRoleDTO> respo= securityPlatformRoleService.loadRoleByUserId(paramMap );
			 List<PlatformRoleDTO> platformRoleLt = respo.getData();
			 for(PlatformRoleDTO platformRole : platformRoleLt){
				loginUserDetails.addRole(platformRole.getPr_name());
			}
			 HashMap<String, Object> paramMap2 = new HashMap<>();
			 
			paramMap2.put("pub_id",  platformUserBase.getPub_id());
			paramMap2.put("par_id", SystemConstants.AUTHORITYRESOURCE_ROOT_ID);
			paramMap2.put("par_platform", SystemConstants.PLATFORM_CODE);
			paramMap2.put("pr_dr", SystemConstants.DELETE_NO);
			paramMap2.put("pr_status", SystemConstants.ROLE_STATUS_ENABLE);
			paramMap2.put("par_dr", SystemConstants.DELETE_NO);
			paramMap2.put("par_status", SystemConstants.AUTHORITYRESOURCE_STATUS_ENABLE);
			
			SecurityResponse<MenuDTO> menuRespo = securityPlatformAuthorityResourceService.loadAuthorityResourceByUserId(paramMap2);
			 
			// 获取用户可见的树菜单
			loginUserDetails.setMenuDTOLt(menuRespo.getData());
		} catch (Exception e) {
			log.error("获取用户信息出错", e);
		}
		
		return loginUserDetails;
	}
}
