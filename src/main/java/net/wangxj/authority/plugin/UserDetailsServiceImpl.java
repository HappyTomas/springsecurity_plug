package net.wangxj.authority.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
import net.wangxj.util.jersey.JerseyClient;
import net.wangxj.util.jersey.RequestMethod;

public class UserDetailsServiceImpl implements UserDetailsService {

	private Logger log = Logger.getLogger(UserDetailsServiceImpl.class);
	
	private String platform_sign;
	
	private String authority_service_url;

	/**
	 * 根据Cas返回的登录用户名，为用户信息设置其拥有的相应权限
	 */
	@Override
	public UserDetails loadUserByUsername(String login_email) throws UsernameNotFoundException {
		LoginUserDetails loginUserDetails = new LoginUserDetails();
		List<String> pathList = new ArrayList<>();
		pathList.add("users");
		pathList.add(login_email);
		pathList.add("info");
		String userInfo = JerseyClient.rest(RequestMethod.GET, authority_service_url, pathList, null, null, null);
		log.debug("用户信息:-->" + userInfo);
		if("".equals(userInfo) || "null".equals(userInfo) || userInfo == null){
			throw new UsernameNotFoundException("未找到用户信息");
		}
		Map userMap = JSONObject.parseObject(userInfo, Map.class);
		loginUserDetails.setUser_id((String)userMap.get("user_uuid"));
		loginUserDetails.setUsername((String)userMap.get("user_login_name"));
		loginUserDetails.setRegisterdate((String)userMap.get("user_add_time"));
		//查询平台信息
		String platformInfoBySignUrl = authority_service_url + "/platforms/" + platform_sign + "/info";
		String platformInfo = JerseyClient.rest(RequestMethod.GET, platformInfoBySignUrl, null, null, null, null);
		log.debug("平台" + platform_sign + "信息:" + platformInfo);
		Map platMap = JSONObject.parseObject(platformInfo, Map.class);
		String platUuid = (String) platMap.get("platform_uuid");
		//获取用户拥有的角色
		List<String> userPathList = new ArrayList<>();
		userPathList.add("users");
		userPathList.add(loginUserDetails.getUser_id());
		userPathList.add(platUuid);
		userPathList.add("roles");
		String rolesJson = JerseyClient.rest(RequestMethod.GET, authority_service_url, userPathList, null, null, null);
		log.debug("用户:" + loginUserDetails.getUsername() + "拥有的角色:" + rolesJson);
		Map rolesDataMap = JSONObject.parseObject(rolesJson, Map.class);
		String rolesStr = JSONObject.toJSONString(rolesDataMap.get("data"));
		List<Map> rolesMapList = JSONObject.parseArray(rolesStr, Map.class);
		for (Map roleMap : rolesMapList) {
			loginUserDetails.addRole((String)roleMap.get("role_name"));
		}
		
		return loginUserDetails;
	}

	public String getPlatform_sign() {
		return platform_sign;
	}

	public void setPlatform_sign(String platform_sign) {
		this.platform_sign = platform_sign;
	}

	public String getAuthority_service_url() {
		return authority_service_url;
	}

	public void setAuthority_service_url(String authority_service_url) {
		this.authority_service_url = authority_service_url;
	}
	
	
}
