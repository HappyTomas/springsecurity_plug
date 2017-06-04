package net.wangxj.authority.plugin;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;



public class UserAccessDeniedHandler implements AccessDeniedHandler {

	private static Logger log = Logger.getLogger(UserAccessDeniedHandler.class);
	
	private String errorPage;
	
	
//访问失败相应处理
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		
		boolean isAjax = isAjaxRequest(request);
		if (isAjax) {
			response.setCharacterEncoding("UTF-8");
			response.setContentType("application/text;charset=UTF-8");
			response.getWriter().write(accessDeniedException.getMessage());
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.getWriter().close();
		} else {
			request.setAttribute("isAjaxRequest", isAjax);
			request.setAttribute("message", accessDeniedException.getMessage());
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
			dispatcher.forward(request, response);
		}
	}

	private boolean isAjaxRequest(HttpServletRequest request) {
        String header = request.getHeader("X-Requested-With");
        if (header != null && "XMLHttpRequest".equals(header)){
        	return true;
        } else{
        	return false;
        }
    }

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}
}
