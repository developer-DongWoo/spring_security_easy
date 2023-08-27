Spring security easy mode

## 개발 목적
<hr>
로그인과 회원가입.

그리고 리소스를 요청할 수 있는 권한에 대한 것은 어떤 서비스를 개발하든
고민하게 됩니다.

어떤 서비스를 개발하든 필요한 내용인 만큼, 프로젝트마다 중복되고 겹치는 부분이
많이 생길 수 밖에 없는데, 그럼에도 불구하고 매 번 같은 코드를 쳐야 한다면 
매우 비효율적인 작업이 될 수 밖에 없을 것입니다.

또한 많은 주니어 개발자들이 포트폴리오를 위한 프로젝트를 진행하면서 
Spring security 를 통곡의 벽으로 여기는 경우를 많이 보았기에 
Easy Mode의 개발 필요성을 느끼게 되었습니다.


주의: 귀하의 프로젝트에 적용하려면,
경로를 수정하거나 일부 코드가 수정되어야 할 수 있습니다.

## 주요 의존성
<hr>
-DataBase : H2

-ORM : Spring JPA

-인증 방식 : JWT


## 사용법
<hr>
<h3 style="color:green">
- config 패키지의 AllowedOrigins, OAuth2Configuration, SecurityConfiguration 을 이용해 손쉽게 Security 세팅이 가능하도록 설계하였습니다.
</h3>
1. application.yml 의 ${JWT_SECRET_KEY}를 사용하기 위해 환경변수를 설정해줍니다.
2. AllowedOrigins (security.securityFrame.Auth.config 경로)에서 접근 가능한 
Origin을 설정해줍니다.(예:프론트엔드 측 url) 이외의 origin에서 요청이 오면 차단할 수 있습니다.

3. SecurityConfiguration 클래스를 통해 cors 설정이 가능합니다.
AllowedOrigins 의 설정 이외에, allowed method 를 비롯한
전체적인 인증, 인가 흐름을 정의할 수 있습니다.

4. LoginDto를 통해 로그인 시 받을 값을 정의할 수 있습니다.
5. LoginResponseDto를 통해 로그인 성공 시 반환할 값을 정의할 수 있습니다.
6. TokenProvider는 토큰의 생성과 인증 등의 기능을 담당합니다. 
여기서 토큰 생성 시 토큰 안에 넣을 정보를 정의할 수 있습니다.
verifyRefreshToken에서는 Refresh Token을 DB와 연관지어 검증하도록 설정할 수 있습니다.
만약 토큰이 탈취당한 경우 DB에 저장된 Refresh Token을 삭제하여 AccessToken 재발급을 방지합니다.
7. role 패키지에서 권한을 정의할 수 있습니다. 현재 USER, PARTNER로 정의되어 있으며, 만약 PARTNER 회원이라면 USER와 PARTNER 권한 모두를 가집니다.
8. TokenPrefix를 통해 토큰의 인증타입을 설정할 수 있습니다.
9. ExceptionCode enum 파일을 이용해서 다양한 예외코드를 추가할 수 있습니다.
10. 각 Entity에서 BaseEntity를 상속함으로써, 자동으로 데이터 생성일,
수정일이 입력됩니다.
11. Member 패키지에서 회원가입을 위한 기본적인 내용이 포함되어있습니다. 회원가입 시
받을 값을 추가할 수 있습니다.

12. OAuth2Configuration ENUM 파일에서는 구글 OAUTH 리디렉션 URL을 설정할 수 있습니다.
13. OAuth2MemberSuccessHandler 클래스에서 더 상세한 설정이 가능합니다.
14. application.yml 에서 redirect-uri, 구글에서 생성한 client-id, client-secret, scope를 환경변수에서 가져올 수 있도록 해야합니다.