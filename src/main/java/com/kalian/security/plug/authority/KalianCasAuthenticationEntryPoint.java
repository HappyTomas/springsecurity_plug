package com.kalian.security.plug.authority;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.util.Assert;

import com.kalian.security.plug.authority.base.SystemConstants;



public class KalianCasAuthenticationEntryPoint extends CasAuthenticationEntryPoint{

	
		
	
		public void afterPropertiesSet() throws Exception {
			Assert.hasLength(getLoginUrl(), "loginUrl must be specified");
			Assert.notNull(getServiceProperties(), "serviceProperties must be specified");
			/*Assert.notNull(this.serviceProperties.getService(),
					"serviceProperties.getService() cannot be null.");*/
		}
		
		protected String createServiceUrl(final HttpServletRequest request,
				final HttpServletResponse response) {
			
			String loginUrl = getLoginUrl();
//			根据域名生成要跳转的serviceURL向cas传递运营商编号
			String url = request.getRequestURL().toString();
			String serviceUrl = "";
			String serviceBrand = "";
			
			if(url.indexOf("https://") >= 0){
				serviceUrl = url.substring(8,url.length() - request.getRequestURI().length());
			}
			if(url.indexOf("http://") >= 0){
				serviceUrl = url.substring(7,url.length() - request.getRequestURI().length());
			}
			
			Properties proper = new Properties();
//			根据域名读取配置文件，查找运营商编号
			String classpath = this.getClass() .getClassLoader().getResource("properties/domain.properties").getPath();
			try {
				proper.load(new FileInputStream(new File(classpath)));
				
				serviceBrand = proper.getProperty(serviceUrl);
//				给SystemConstants设置运营商编号
				SystemConstants.GLOBAL_ORG_ID = serviceBrand;
			} catch (FileNotFoundException e) {
				
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			if(!getLoginUrl().contains("serviceBrand")){
				loginUrl += "?serviceBrand=" +serviceBrand;
			}
			
			setLoginUrl(loginUrl);
			
			ServiceProperties servicePro = new ServiceProperties();
			servicePro.setService(url+"login/cas");
			this.setServiceProperties(servicePro);
			
			return CommonUtils.constructServiceUrl(null, response,
					getServiceProperties().getService(), null,
					getServiceProperties().getArtifactParameter(),
					getEncodeServiceUrlWithSessionId());
		}
}