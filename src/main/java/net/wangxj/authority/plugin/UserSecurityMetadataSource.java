package net.wangxj.authority.plugin;

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

import com.alibaba.fastjson.JSONObject;

import net.wangxj.util.jersey.JerseyClient;
import net.wangxj.util.jersey.RequestMethod;

@Component
public class UserSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	private static Logger log = Logger.getLogger(UserSecurityMetadataSource.class);
	
	private String authority_service_url;
	private String platform_sign;
	
	private static Map<String, String> resource_url_map = null;
	
	private static Collection<ConfigAttribute> ABSOLUTE_SECURITY_CONFIGATTRIBUTES;
	
	static{
		ABSOLUTE_SECURITY_CONFIGATTRIBUTES = new ArrayList<>();
		ABSOLUTE_SECURITY_CONFIGATTRIBUTES.add(new SecurityConfig("ABSOLUTE_SECURITY_" + new Random().nextFloat()));
	}
	
	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		
		String platformInfoBySignUrl = authority_service_url + "/platforms/" + platform_sign + "/info";
		String platformInfo = JerseyClient.rest(RequestMethod.GET, platformInfoBySignUrl, null, null, null, null);
		log.debug("平台" + platform_sign + "信息:" + platformInfo);
		Map platMap = JSONObject.parseObject(platformInfo, Map.class);
		String platUuid = (String) platMap.get("platform_uuid");
		//查询平台下的所有资源列表
		List<String> pathList = new ArrayList<>();
		pathList.add("platforms");
		pathList.add(platUuid);
		pathList.add("resources");
		pathList.add("list");
		String resources = JerseyClient.rest(RequestMethod.GET, authority_service_url, pathList, null, null, null);
		log.debug("平台" + platMap.get("platform_name") + "下的所有资源:" + resources);
		List<Map> resourceList = JSONObject.parseArray(resources, Map.class);
		
		resource_url_map = new HashMap<>();
		
		String checkCode;
		for(Map resMap : resourceList){
			String resUrl = (String)resMap.get("resource_url");
			checkCode = getCheckCode(resUrl);
			resource_url_map.put(checkCode, (String)resMap.get("resource_uuid"));
		}
		
		return ABSOLUTE_SECURITY_CONFIGATTRIBUTES;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object paramObject) throws IllegalArgumentException {
		
		Collection<ConfigAttribute> configAttributeLt = new ArrayList<>();
		
		String url = ((FilterInvocation)paramObject).getRequestUrl();
		String checkCode = getCheckCode(url);
		
		log.debug("用户请求的URL地址：" + url + ", 权限验证标识：" + checkCode);
		
		//获取访问该地址所需的权限
		String res_uuid = resource_url_map.get(checkCode);
		if(res_uuid != null){
			try {
				List<String> pathList = new ArrayList<>();
				pathList.add("resources");
				pathList.add(res_uuid);
				pathList.add("roles");
				String needRoles = JerseyClient.rest(RequestMethod.GET, authority_service_url, pathList, null, null, null);
				log.debug("访问" + checkCode +"需要的角色:" + needRoles +"之一");
				Map dataMap = JSONObject.parseObject(needRoles, Map.class);
				Object listRolesObj = dataMap.get("data");
				List<Map> listRolesMap = JSONObject.parseArray(JSONObject.toJSONString(listRolesObj), Map.class);
				for(Map roleMap : listRolesMap){
					configAttributeLt.add(new SecurityConfig((String)roleMap.get("role_name")));
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
	
	public String getCheckCode(final String url) {
		String checkCode;
		String bakUrl = url;
		//剔除查询串
		if(bakUrl.indexOf("?") != -1){
			bakUrl = bakUrl.substring(0, bakUrl.lastIndexOf("?"));
		}
		if(bakUrl.indexOf("/") != 0){
			bakUrl = "/" + bakUrl;
		}
		if(bakUrl.lastIndexOf("/") != (bakUrl.length() - 1)){
			bakUrl = bakUrl + "/";
		}
		checkCode = bakUrl.toUpperCase();
		log.debug(url + "的checkCode:-->" + checkCode);
		return checkCode;
	}

	public String getAuthority_service_url() {
		return authority_service_url;
	}

	public void setAuthority_service_url(String authority_service_url) {
		this.authority_service_url = authority_service_url;
	}

	public String getPlatform_sign() {
		return platform_sign;
	}

	public void setPlatform_sign(String platform_sign) {
		this.platform_sign = platform_sign;
	}
	
	
}
