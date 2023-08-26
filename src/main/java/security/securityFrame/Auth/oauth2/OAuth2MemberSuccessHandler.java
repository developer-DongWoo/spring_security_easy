package security.securityFrame.Auth.oauth2;


import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import security.securityFrame.Auth.provider.TokenProvider;
import security.securityFrame.Auth.role.MemberRole;
import security.securityFrame.Auth.role.Role;
import security.securityFrame.Auth.role.RoleService;
import security.securityFrame.member.entity.Member;
import security.securityFrame.member.service.MemberService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

import static security.securityFrame.Auth.utils.TokenPrefix.*;
@AllArgsConstructor
@Slf4j
public class OAuth2MemberSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final MemberService memberService;
    private final RoleService roleService;
    private final TokenProvider tokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        var oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = String.valueOf(oAuth2User.getAttributes().get("email"));
        //Todo 가져오고싶은 것 추가 가능

        Member member;

        // 가입했던 사람인지?
        if (memberService.isExistMember(email)) {
            member = memberService.findMemberByEmail(email);
        } else {
            member = createNewMember(email);
            memberService.createMember(member);
        }

        redirect(request,response,member);
    }
    private void redirect(HttpServletRequest request,
                          HttpServletResponse response,
                          Member member) throws IOException {
        String accessToken = tokenProvider.delegateAccessToken(member);
        String refreshToken = tokenProvider.delegateRefreshToken(member);
        String loginResponse = tokenProvider.getLoginResponseJson(member);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(AUTHORIZATION.getType(), BEARER.getType() + accessToken);

        response.setHeader("Set-Cookie", REFRESH.getType() + "=" + refreshToken +
                "; Path=/; Secure; SameSite=None; HttpOnly; Max-Age=3600;");

        response.getWriter().write(loginResponse);

        String uri = createURI(accessToken);

        log.info("# Google Authenticated Successfully!");
        getRedirectStrategy().sendRedirect(request, response, uri);

    }

    private Member createNewMember(String email) {
        Member member = new Member();
        member.setEmail(email);
        member.setPassword(generateRandomPassword());
        //Todo Member Entity 에 맞추어서 추가

        Role userRole = roleService.findUserRole();
        List<MemberRole> memberRoles = memberService.addedMemberRole(member,userRole);
        member.setMemberRoles(memberRoles);

        return member;
    }

    private String generateRandomPassword() {
        int length = 10;
        String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";

        SecureRandom random = new SecureRandom();
        String password = random
                .ints(length, 0, charset.length())
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();

        return password;
    }

    private String createURI(String accessToken) {
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("access_token", accessToken);

        // 컨트롤러로 보낸 후 프론트로 리다이렉트 시도
        return UriComponentsBuilder.newInstance()
                // 프론트 도메인
                .scheme("http")
                .host("http://localhost:8081") // s3 엔드포인트
//                .port(5173)
                .path("/oauth2/authorization/google/success")
                .queryParams(queryParams)
                .build().toUri()
                .toString();
    }
}
