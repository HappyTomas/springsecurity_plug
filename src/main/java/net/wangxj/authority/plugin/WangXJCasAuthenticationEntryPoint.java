package net.wangxj.authority.plugin;

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

public class WangXJCasAuthenticationEntryPoint extends CasAuthenticationEntryPoint{
	
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
			
			ServiceProperties servicePro = new ServiceProperties();
			servicePro.setService(url+"login/cas");
			this.setServiceProperties(servicePro);
			
			return CommonUtils.constructServiceUrl(null, response,
					getServiceProperties().getService(), null,
					getServiceProperties().getArtifactParameter(),
					getEncodeServiceUrlWithSessionId());
		}
}