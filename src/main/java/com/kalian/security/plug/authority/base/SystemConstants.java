package com.kalian.security.plug.authority.base;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import com.estock.thirdchannel.commons.utils.CommonsConfig;

public class SystemConstants {
	
	private static final Logger log = Logger.getLogger(SystemConstants.class);
	
	/**
	 * 是否删除（0否，1是）
	 */
	public static final String DELETE_NO = "0";
	public static final String DELETE_YES = "1";
	/**
	 * 是否全局（0否，1是）
	 */
	public static final String GLOBAL_NO = "0";
	public static final String GLOBAL_YES = "1";
	/**
	 * 权限状态
	 */
	public static final String AUTHORITYRESOURCE_STATUS_ENABLE = "00";
	public static final String AUTHORITYRESOURCE_STATUS_DISABLE = "01";
	/**
	 * 资源反转状态
	 */
	public static final String AUTHORITYRESOURCE_REVERSE_NO = "0";
	public static final String AUTHORITYRESOURCE_REVERSE_YES = "1";
	/**
	 * 角色状态
	 */
	public static final String ROLE_STATUS_ENABLE = "00";
	public static final String ROLE_STATUS_DISABLE = "01";
	
	/**
	 * 平台权限资源根节点编号
	 */
	
	public static final String AUTHORITYRESOURCE_ROOT_ID;
	/**
	 * 平台编码
	 */
	
	public static final String PLATFORM_CODE;
	/**
	 * 全局运营商编号
	 */
	public static String GLOBAL_ORG_ID = "";
	
	static{
		AUTHORITYRESOURCE_ROOT_ID = CommonsConfig.get("platform.authorityresource.rootid");
		PLATFORM_CODE = CommonsConfig.get("platform.system.code");
		if(StringUtils.isEmpty(AUTHORITYRESOURCE_ROOT_ID)){
			log.error("AUTHORITYRESOURCE_ROOT_ID must be specified");
			System.exit(0);
		}
		if(StringUtils.isEmpty(PLATFORM_CODE)){
			log.error("PLATFORM_TPOSWEB_CODE must be specified");
			System.exit(0);
		}
	}
	
	
	public void sftpUpload(){
		
	}
}
