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
@Order(30)
public class OwnerFilter implements Filter {

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String[] path = request.getServletPath().split("/");
		if(!(path.length == 4
           && "Put".equalsIgnoreCase(request.getMethod())
		   && path[3].equals(request.getUserPrincipal().getName()))) {
		    	response.sendError(403, "You can not to change this accaunt!!!");
			    return;	
		    }
		chain.doFilter(request, response);
	}
}
