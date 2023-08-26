package security.securityFrame.Auth.memberDetail;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import security.securityFrame.Auth.utils.MemberAuthorityUtil;
import security.securityFrame.exception.BusinessLogicException;
import security.securityFrame.exception.ExceptionCode;
import security.securityFrame.member.entity.Member;
import security.securityFrame.member.repository.MemberRepository;

import java.util.Optional;

@Component
@AllArgsConstructor
public class MemberDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final MemberAuthorityUtil authorityUtil;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> optionalMember = memberRepository.findByEmail(username);

        Member findMember = optionalMember.orElseThrow(
                () -> new BusinessLogicException(ExceptionCode.NOT_FOUND_ERROR)
        );

        return new MemberDetails(findMember, authorityUtil);
    }
}
