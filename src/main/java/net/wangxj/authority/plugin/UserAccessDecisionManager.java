package net.wangxj.authority.plugin;

import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class UserAccessDecisionManager implements AccessDecisionManager  {

	private static Logger log = Logger.getLogger(UserAccessDecisionManager.class);
	
	
	//判断用户是否有权限访问相应的URL
	@Override
	public void decide(Authentication authentication, Object paramObject, Collection<ConfigAttribute> configAttributes)
					throws AccessDeniedException, InsufficientAuthenticationException {
		
		if(configAttributes==null){
			return;
		}
		Iterator<ConfigAttribute> it = configAttributes.iterator();
		while(it.hasNext()){
			String needRole = it.next().getAttribute();
			log.debug("访问该页面需要的权限：" + needRole);
			//获取用户所有的权限
			for(GrantedAuthority ga : authentication.getAuthorities()){
				log.debug("当前用户拥有的角色：" + ga.getAuthority());
				if(needRole.equalsIgnoreCase(ga.getAuthority())){
					return;
				}
			}
		}
		throw new AccessDeniedException("没有权限");
	}

	@Override
	public boolean supports(ConfigAttribute paramConfigAttribute) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean supports(Class<?> paramClass) {
		// TODO Auto-generated method stub
		return true;
	}

}
