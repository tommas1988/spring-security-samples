package login.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        if (response.isCommitted()) {
            throw new RuntimeException("Cannot save jwt login token since response is already committed");
        }

        JwtAuthenticationToken jwtAuthenticationToken =  new JwtAuthenticationToken(SecurityContextHolder.getContext().getAuthentication());
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        jwtAuthenticationToken.saveToken(response);

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
