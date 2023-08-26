package security.securityFrame.Auth.memberDetail;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import security.securityFrame.Auth.utils.MemberAuthorityUtil;
import security.securityFrame.member.entity.Member;

import java.util.Collection;

public class MemberDetails extends Member implements UserDetails {
    private final MemberAuthorityUtil authorityUtil;

    public MemberDetails(Member member, MemberAuthorityUtil authorityUtil) {
        this.authorityUtil = authorityUtil;
        setMemberId(member.getMemberId());
        setMemberRoles(member.getMemberRoles());
        setEmail(member.getEmail());
        setPassword(member.getPassword());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorityUtil.createAuthorities(this.getRoles());
    }

    @Override
    public String getUsername() {
        return getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
