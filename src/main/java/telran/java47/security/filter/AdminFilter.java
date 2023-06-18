package telran.java47.security.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;

@Component
@RequiredArgsConstructor
@Order(20)
public class AdminFilter implements Filter {
	
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String[] path = request.getServletPath().split("/");
		if (checkEndPoint(request.getMethod(),path)) {
			System.out.println("Inside");
		UserAccount userAccount =userAccountRepository.findById(request.getUserPrincipal().getName()).orElse(null);
		boolean check = checkAdmin(userAccount.getRoles());
		    if (!(check || 
		    		((path.length == 4
                      && "Delete".equalsIgnoreCase(request.getMethod()))
		    		  && path[3].equals(request.getUserPrincipal().getName())))) {
		    	response.sendError(403, "You must have rules of administrator!!!");
			    return;	
		    }
		}
		chain.doFilter(request, response);

	}
	private boolean checkAdmin(Set<String> roles) {
		return roles.contains("ADMINISTRATOR");
	}
	private boolean checkEndPoint(String method, String[] path) {
		return ((path.length == 6 && "Put".equalsIgnoreCase(method) && path[4].equalsIgnoreCase("role"))||
				("Delete".equalsIgnoreCase(method) && path[2].equalsIgnoreCase("user"))||
				((path.length == 4 && "Delete".equalsIgnoreCase(method))));
	}
	
}
