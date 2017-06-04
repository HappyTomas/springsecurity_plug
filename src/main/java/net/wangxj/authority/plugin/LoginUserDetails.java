package net.wangxj.authority.plugin;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


/**
 * 登录用户信息(用户名，密码，所拥有的角色，可见菜单)
 * @author kaliankeji
 *
 */
public class LoginUserDetails implements UserDetails {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8214154934715796505L;

	private String user_id;
	private String username;
	private String password;
	private String registerdate;
	private List<String> roleLt = new ArrayList<>();
	
	public String getUser_id() {
		return user_id;
	}
	public void setUser_id(String user_id) {
		this.user_id = user_id;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getRegisterdate() {
		return registerdate;
	}
	public void setRegisterdate(String registerdate) {
		this.registerdate = registerdate;
	}
	public String getRole() {
		return ArrayUtils.toString(this.roleLt);
	}
	public List<String> getRoleLt() {
		return roleLt;
	}
	public void setRoleLt(List<String> roleLt) {
		this.roleLt = roleLt;
	}
	public void addRole(String role){
		this.roleLt.add(role);
	}
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		ArrayList<GrantedAuthority> list = new ArrayList<>();
		
		GrantedAuthorityImpl grantedAuthority = null;
		
		for(String s : roleLt){
			grantedAuthority = new GrantedAuthorityImpl();
			grantedAuthority.setAuthority(s);
			list.add(grantedAuthority);
		}
		
		return list;
	}
	@Override
	public String getPassword() {
		return password;
	}
	@Override
	public String getUsername() {
		return username;
	}
	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}
	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}
	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}
	
	@Override
	public int hashCode() {
		return username.hashCode(); 
	}
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof LoginUserDetails) {  
	        return username.equals(((LoginUserDetails) obj).username);  
	    }  
	    return false; 
	}
}
