package security.securityFrame.member.mapper;

import org.mapstruct.Mapper;
import org.springframework.stereotype.Component;
import security.securityFrame.member.dto.SignupDto;
import security.securityFrame.member.dto.SignupResponseDto;
import security.securityFrame.member.entity.Member;


@Mapper(componentModel = "spring")
@Component
public interface MemberMapper {
    Member signupDtoToMember(SignupDto requestBody);
    SignupResponseDto memberToSignupResponseDto(Member member);
}
