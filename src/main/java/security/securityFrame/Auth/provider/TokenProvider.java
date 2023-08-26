package security.securityFrame.Auth.provider;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import security.securityFrame.Auth.dto.LoginResponseDto;
import security.securityFrame.helper.util.JsonUtil;
import security.securityFrame.member.entity.Member;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Component
public class TokenProvider {

    @Getter
    @Value("${jwt.key}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;

    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    public String encodedBase64SecretKey() {
        return Encoders.BASE64.encode(
                secretKey.getBytes(StandardCharsets.UTF_8)
        );
    }

    public String delegateAccessToken(Member member) {
        Map<String, Object> claims = new HashMap<>(); //토큰에 넣을 정보
        claims.put("username", member.getEmail()); //username 으로 이메일 사용
        claims.put("memberId", member.getMemberId());
        claims.put("roles", member.getRoles());

        String subject = String.valueOf(member.getMemberId());
        Date expiration = getTokenExpiration(accessTokenExpirationMinutes);
        String base64EncodedSecretKey = encodedBase64SecretKey();

        return generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);
    }


    public String delegateRefreshToken(Member member) {
        String subject = member.getEmail();
        Date expiration = getTokenExpiration(refreshTokenExpirationMinutes);
        String base64EncodedSecretKey = encodedBase64SecretKey();

        return generateRefreshToken(subject,expiration,base64EncodedSecretKey);
    }
    private String generateAccessToken(Map<String, Object> claims,
                                       String subject,
                                       Date expiration,
                                       String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }


    private String generateRefreshToken(String subject,
                                        Date expiration,
                                        String base64EncodedSecretKey) {
    Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

    return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(Calendar.getInstance().getTime())
            .setExpiration(expiration)
            .signWith(key)
            .compact();
    }
    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        Key key = Keys.hmacShaKeyFor(keyBytes);

        return key;
    }
    private Date getTokenExpiration(int expirationMinutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);

        return calendar.getTime();
    }

    public Jws<Claims> getClaims(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);
    }
    public boolean isExpired(Jws<Claims> claims) {
        Date expiration = claims.getBody().getExpiration();
        return expiration.before(Calendar.getInstance().getTime());
    }

    public String getLoginResponseJson(Member member) {
        String role = member.getRoleName();

        //로그인 시 추가하고 싶은 내용이 있으면 작성할 수 있음
        LoginResponseDto responseDto = new LoginResponseDto(role);
        return JsonUtil.toJson(responseDto, LoginResponseDto.class);
    }
}
