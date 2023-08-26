package security.securityFrame.member.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

@Getter
@AllArgsConstructor
public class SignupDto {
    @NotBlank(message = "이메일을 입력해주세요.")
    @Email(message = "올바른 이메일 형식이 아닙니다.")
    private String email;

    @NotBlank(message = "비밀번호를 입력해주세요.")
    @Pattern(regexp = "(?=.*[A-Za-z])(?=.*[0-9])(?=.*\\W).{8,20}",
            message = "비밀번호는 영문, 숫자, 특수문자를 포함하여 8자 이상 작성해주세요.")
    private String password;

    //Todo 회원가입에 필요한 정보를 추가할 수 있음

}
