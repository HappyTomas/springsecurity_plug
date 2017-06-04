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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.NullStatelessTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.*;
import org.springframework.util.Assert;


public class WangXJCasAuthenticationProvider implements AuthenticationProvider,
		InitializingBean, MessageSourceAware {

	private static final Log logger = LogFactory.getLog(WangXJCasAuthenticationProvider.class);

	private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService;

	private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private StatelessTicketCache statelessTicketCache = new NullStatelessTicketCache();
	private String key;
	private TicketValidator ticketValidator;
	private ServiceProperties serviceProperties;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	/**
	 * 初始化时验证xml配置的一些验证
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.authenticationUserDetailsService,
				"authenticationUserDetailsService必须设置");
		Assert.notNull(this.ticketValidator, "ticket验证器必须设置");
		Assert.notNull(this.statelessTicketCache, "statelessTicketCache必须设置");
		Assert.hasText(
				this.key,
				"A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated");
		Assert.notNull(this.messages, "A message source must be set");
	}

	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}

		if (authentication instanceof UsernamePasswordAuthenticationToken
				&& (!CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER
						.equals(authentication.getPrincipal().toString()) && !CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER
						.equals(authentication.getPrincipal().toString()))) {
			// UsernamePasswordAuthenticationToken not CAS related
			return null;
		}

		// If an existing CasAuthenticationToken, just check we created it
		if (authentication instanceof CasAuthenticationToken) {
			if (this.key.hashCode() == ((CasAuthenticationToken) authentication)
					.getKeyHash()) {
				return authentication;
			}
			else {
				throw new BadCredentialsException(
						messages.getMessage("CasAuthenticationProvider.incorrectKey",
								"The presented CasAuthenticationToken does not contain the expected key"));
			}
		}

		// 验证凭证是否存在
		if ((authentication.getCredentials() == null)
				|| "".equals(authentication.getCredentials())) {
			throw new BadCredentialsException(messages.getMessage(
					"CasAuthenticationProvider.noServiceTicket",
					"Failed to provide a CAS service ticket to validate"));
		}

		boolean stateless = false;

		if (authentication instanceof UsernamePasswordAuthenticationToken
				&& CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER.equals(authentication
						.getPrincipal())) {
			stateless = true;
		}

		CasAuthenticationToken result = null;

		if (stateless) {
			// Try to obtain from cache
			result = statelessTicketCache.getByTicketId(authentication.getCredentials()
					.toString());
		}

		if (result == null) {
			result = this.authenticateNow(authentication);
			result.setDetails(authentication.getDetails());
		}

		if (stateless) {
			// Add to cache
			statelessTicketCache.putTicketInCache(result);
		}

		return result;
	}
	
	//向cas服务器验证token核心逻辑
	private CasAuthenticationToken authenticateNow(final Authentication authentication)
			throws AuthenticationException {
		try {
			//向cas服务器验证Token，返回用户信息
			final Assertion assertion = this.ticketValidator.validate(authentication
					.getCredentials().toString(), getServiceUrl(authentication));
			//调用自定义逻辑UserDetailServiceImpl返回登录用户信息
			final UserDetails userDetails = loadUserByAssertion(assertion);
			
			userDetailsChecker.check(userDetails);
			return new CasAuthenticationToken(this.key, userDetails,
					authentication.getCredentials(),
					authoritiesMapper.mapAuthorities(userDetails.getAuthorities()),
					userDetails, assertion);
		}
		catch (final TicketValidationException e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}
	}

	/**
	 * 向cas服务器验证token时生成serviceUrl
	 * @param authentication
	 * @return
	 */
	private String getServiceUrl(Authentication authentication) {
		
		if(authentication instanceof WangXJUsernamePasswordAuthenticationToken)
		{
			WangXJUsernamePasswordAuthenticationToken kalianAuth = (WangXJUsernamePasswordAuthenticationToken) authentication;
			String backUrl = kalianAuth.getBackUrl();
			ServiceProperties service = new ServiceProperties();
			service.setService(backUrl);
			this.serviceProperties = service;
		}
		
		String serviceUrl;
		if (authentication.getDetails() instanceof ServiceAuthenticationDetails) {
			serviceUrl = ((ServiceAuthenticationDetails) authentication.getDetails())
					.getServiceUrl();
		}
		else if (serviceProperties == null) {
			throw new IllegalStateException(
					"serviceProperties不可为空");
		}
		else if (serviceProperties.getService() == null) {
			throw new IllegalStateException(
					"serviceProperties.getService()不可为空");
		}
		else {
			serviceUrl = serviceProperties.getService();
		}
		if (logger.isDebugEnabled()) {
			logger.debug("serviceUrl = " + serviceUrl);
		}
		return serviceUrl;
	}

	//获取用户信息，响应逻辑由自定义
	protected UserDetails loadUserByAssertion(final Assertion assertion) {
		final CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(
				assertion, "");
		return this.authenticationUserDetailsService.loadUserDetails(token);
	}

	@SuppressWarnings("unchecked")
	/**
	 * Sets the UserDetailsService to use. This is a convenience method to invoke
	 */
	public void setUserDetailsService(final UserDetailsService userDetailsService) {
		this.authenticationUserDetailsService = new UserDetailsByNameServiceWrapper(
				userDetailsService);
	}

	public void setAuthenticationUserDetailsService(
			final AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService) {
		this.authenticationUserDetailsService = authenticationUserDetailsService;
	}

	public void setServiceProperties(final ServiceProperties serviceProperties) {
		this.serviceProperties = serviceProperties;
	}

	protected String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public StatelessTicketCache getStatelessTicketCache() {
		return statelessTicketCache;
	}

	protected TicketValidator getTicketValidator() {
		return ticketValidator;
	}

	public void setMessageSource(final MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setStatelessTicketCache(final StatelessTicketCache statelessTicketCache) {
		this.statelessTicketCache = statelessTicketCache;
	}

	public void setTicketValidator(final TicketValidator ticketValidator) {
		this.ticketValidator = ticketValidator;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	public boolean supports(final Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class
				.isAssignableFrom(authentication))
				|| (CasAuthenticationToken.class.isAssignableFrom(authentication))
				|| (CasAssertionAuthenticationToken.class
						.isAssignableFrom(authentication));
	}
}
