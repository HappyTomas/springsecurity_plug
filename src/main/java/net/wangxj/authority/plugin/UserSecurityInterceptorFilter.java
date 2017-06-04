package net.wangxj.authority.plugin;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.UrlUtils;

public class UserSecurityInterceptorFilter extends AbstractSecurityInterceptor implements Filter{
	
	
	private FilterInvocationSecurityMetadataSource securityMetadataSource;
	
	private static Logger log = Logger.getLogger(UserSecurityInterceptorFilter.class);
	
	@Override
	public Class<?> getSecureObjectClass() {
		return FilterInvocation.class;
	}

	@Override
	public SecurityMetadataSource obtainSecurityMetadataSource() {
		return securityMetadataSource;
	}

	public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
		return securityMetadataSource;
	}

	public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource securityMetadataSource) {
		this.securityMetadataSource = securityMetadataSource;
	}
	/**
	 * springsecurity授权逻辑
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		FilterInvocation fi = new FilterInvocation(request, response, chain);
		
		HttpServletRequest hrequest = (HttpServletRequest)request;
		String requestUrl = UrlUtils.buildRequestUrl(hrequest);
		
		UserSecurityMetadataSource userSecurityMetadataSource = (UserSecurityMetadataSource)securityMetadataSource;
		
		String checkCode = userSecurityMetadataSource.getCheckCode(requestUrl).toUpperCase();
		
		log.debug("当前获取到的请求路径：" + checkCode + "," + requestUrl);
		
		invoke(fi);
	}

	public void invoke(FilterInvocation fi) throws IOException, ServletException {
		InterceptorStatusToken token = super.beforeInvocation(fi);
		try {
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
		} finally {
			super.afterInvocation(token, null);
		}
	}
	
	@Override
	public void destroy() {
	}
	
	@Override
	public void init(FilterConfig arg0) throws ServletException {
	}
}
