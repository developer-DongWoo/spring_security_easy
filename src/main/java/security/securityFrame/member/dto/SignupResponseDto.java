package security.securityFrame.member.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupResponseDto {
    private String email;

    //Todo 회원가입 성공 시 반환할 정보를 추가할 수 있음
}
