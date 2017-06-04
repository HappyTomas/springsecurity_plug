package net.wangxj.authority.plugin;

import org.springframework.security.core.GrantedAuthority;


/**
 * 封装用户所拥有的权限（角色）
 * @author kaliankeji
 *
 */
public class GrantedAuthorityImpl implements GrantedAuthority {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4623440635196093894L;
	//权限
	private String authority;
	
	@Override
	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}
}
