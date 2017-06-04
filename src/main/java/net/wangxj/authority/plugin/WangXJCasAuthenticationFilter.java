/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.wangxj.authority.plugin;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationFilter;

import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;


public class WangXJCasAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
		
		/** 表示有状态的用户代理请求，例如web浏览器**/
		public static final String CAS_STATEFUL_IDENTIFIER = "_cas_stateful_";

		/**
		 * 表示无状态的用户代理请求，像远程协议,hessian ,SOAP等, 
		 */
		public static final String CAS_STATELESS_IDENTIFIER = "_cas_stateless_";

		/**
		 * The last portion of the receptor url, i.e. /proxy/receptor
		 */
		private RequestMatcher proxyReceptorMatcher;

		/**
		 * The backing storage to store ProxyGrantingTicket requests.
		 */
		private ProxyGrantingTicketStorage proxyGrantingTicketStorage;

		private String artifactParameter = ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER;

		private boolean authenticateAllArtifacts;

		private AuthenticationFailureHandler proxyFailureHandler = new SimpleUrlAuthenticationFailureHandler();

		// ~ Constructors
		// ===================================================================================================

		public WangXJCasAuthenticationFilter() {
			super("/login/cas");
			setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
		}
		
		/**
		 * 向cas服务器认证成功后的逻辑处理
		 */
		@Override
		protected final void successfulAuthentication(HttpServletRequest request,
				HttpServletResponse response, FilterChain chain, Authentication authResult)
				throws IOException, ServletException {
			boolean continueFilterChain = proxyTicketRequest(
					serviceTicketRequest(request, response), request);
			if (!continueFilterChain) {
				super.successfulAuthentication(request, response, chain, authResult);
				return;
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Authentication success. Updating SecurityContextHolder to contain: "
						+ authResult);
			}
			
			//将返回的用户信息设置到SecurityContext中，并最终设置到Session中
			SecurityContextHolder.getContext().setAuthentication(authResult);

			// Fire event
			if (this.eventPublisher != null) {
				eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
						authResult, this.getClass()));
			}
			//继续执行后面的Filter
			chain.doFilter(request, response);
		}

	
	/**
	 * 向cas服务器认证
	 */
	@Override
	public Authentication attemptAuthentication(final HttpServletRequest request,
			final HttpServletResponse response) throws AuthenticationException,
			IOException {
//		如果请求是一个代理请求进程，则返回空来指示已处理的请求
		if (proxyReceptorRequest(request)) {
			logger.debug("响应代理的请求。。。");
			CommonUtils.readAndRespondToProxyReceptorRequest(request, response,
					this.proxyGrantingTicketStorage);
			return null;
		}

		final boolean serviceTicketRequest = serviceTicketRequest(request, response);
		final String username = serviceTicketRequest ? CAS_STATEFUL_IDENTIFIER
				: CAS_STATELESS_IDENTIFIER;
		String password = obtainArtifact(request);

		if (password == null) {
			logger.debug("Failed to obtain an artifact (cas ticket)");
			password = "";
		}
		
		//验证token时动态根据域名设置serviceUrl
		String backUrl = request.getRequestURL().toString();
		
		final WangXJUsernamePasswordAuthenticationToken authRequest = new WangXJUsernamePasswordAuthenticationToken(
				username, password);
		authRequest.setBackUrl(backUrl);
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

		return this.getAuthenticationManager().authenticate(authRequest);
	}
	
	/**
	 *获取ticket
	 */
	protected String obtainArtifact(HttpServletRequest request) {
		return request.getParameter(artifactParameter);
	}

	/**
	 * Overridden to provide proxying capabilities.
	 */
	protected boolean requiresAuthentication(final HttpServletRequest request,
			final HttpServletResponse response) {
		final boolean serviceTicketRequest = serviceTicketRequest(request, response);
		final boolean result = serviceTicketRequest || proxyReceptorRequest(request)
				|| (proxyTicketRequest(serviceTicketRequest, request));
		if (logger.isDebugEnabled()) {
			logger.debug("requiresAuthentication = " + result);
		}
		return result;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} for proxy requests.
	 * @param proxyFailureHandler
	 */
	public final void setProxyAuthenticationFailureHandler(
			AuthenticationFailureHandler proxyFailureHandler) {
		Assert.notNull(proxyFailureHandler, "proxyFailureHandler cannot be null");
		this.proxyFailureHandler = proxyFailureHandler;
	}

	/**
	 * Wraps the {@link AuthenticationFailureHandler} to distinguish between handling
	 * proxy ticket authentication failures and service ticket failures.
	 */
	@Override
	public final void setAuthenticationFailureHandler(
			AuthenticationFailureHandler failureHandler) {
		super.setAuthenticationFailureHandler(new CasAuthenticationFailureHandler(
				failureHandler));
	}

	public final void setProxyReceptorUrl(final String proxyReceptorUrl) {
		this.proxyReceptorMatcher = new AntPathRequestMatcher("/**" + proxyReceptorUrl);
	}

	public final void setProxyGrantingTicketStorage(
			final ProxyGrantingTicketStorage proxyGrantingTicketStorage) {
		this.proxyGrantingTicketStorage = proxyGrantingTicketStorage;
	}

	public final void setServiceProperties(final ServiceProperties serviceProperties) {
		this.artifactParameter = serviceProperties.getArtifactParameter();
		this.authenticateAllArtifacts = serviceProperties.isAuthenticateAllArtifacts();
	}

	/**
	 * Indicates if the request is elgible to process a service ticket. This method exists
	 * for readability.
	 * @param request
	 * @param response
	 * @return
	 */
	private boolean serviceTicketRequest(final HttpServletRequest request,
			final HttpServletResponse response) {
		boolean result = super.requiresAuthentication(request, response);
		if (logger.isDebugEnabled()) {
			logger.debug("serviceTicketRequest = " + result);
		}
		return result;
	}

	/**
	 * Indicates if the request is elgible to process a proxy ticket.
	 * @param request
	 * @return
	 */
	private boolean proxyTicketRequest(final boolean serviceTicketRequest,
			final HttpServletRequest request) {
		if (serviceTicketRequest) {
			return false;
		}
		final boolean result = authenticateAllArtifacts
				&& obtainArtifact(request) != null && !authenticated();
		if (logger.isDebugEnabled()) {
			logger.debug("proxyTicketRequest = " + result);
		}
		return result;
	}

	/**
	 * Determines if a user is already authenticated.
	 * @return
	 */
	private boolean authenticated() {
		Authentication authentication = SecurityContextHolder.getContext()
				.getAuthentication();
		return authentication != null && authentication.isAuthenticated()
				&& !(authentication instanceof AnonymousAuthenticationToken);
	}

	/**
	 * Indicates if the request is elgible to be processed as the proxy receptor.
	 * @param request
	 * @return
	 */
	private boolean proxyReceptorRequest(final HttpServletRequest request) {
		final boolean result = proxyReceptorConfigured()
				&& proxyReceptorMatcher.matches(request);
		if (logger.isDebugEnabled()) {
			logger.debug("proxyReceptorRequest = " + result);
		}
		return result;
	}

	/**
	 * Determines if the {@link CasAuthenticationFilter} is configured to handle the proxy
	 * receptor requests.
	 *
	 * @return
	 */
	private boolean proxyReceptorConfigured() {
		final boolean result = this.proxyGrantingTicketStorage != null
				&& proxyReceptorMatcher != null;
		if (logger.isDebugEnabled()) {
			logger.debug("proxyReceptorConfigured = " + result);
		}
		return result;
	}

	/**
	 * A wrapper for the AuthenticationFailureHandler that will flex the
	 * {@link AuthenticationFailureHandler} that is used. The value
	 * {@link CasAuthenticationFilter#setProxyAuthenticationFailureHandler(AuthenticationFailureHandler)
	 * will be used for proxy requests that fail. The value
	 * {@link CasAuthenticationFilter#setAuthenticationFailureHandler(AuthenticationFailureHandler)}
	 * will be used for service tickets that fail.
	 *
	 * @author Rob Winch
	 */
	private class CasAuthenticationFailureHandler implements AuthenticationFailureHandler {
		private final AuthenticationFailureHandler serviceTicketFailureHandler;

		public CasAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
			Assert.notNull(failureHandler, "failureHandler");
			this.serviceTicketFailureHandler = failureHandler;
		}

		public void onAuthenticationFailure(HttpServletRequest request,
				HttpServletResponse response, AuthenticationException exception)
				throws IOException, ServletException {
			if (serviceTicketRequest(request, response)) {
				serviceTicketFailureHandler.onAuthenticationFailure(request, response,
						exception);
			}
			else {
				proxyFailureHandler.onAuthenticationFailure(request, response, exception);
			}
		}
	}
	
}