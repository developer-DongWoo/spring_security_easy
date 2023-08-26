package security.securityFrame.Auth.role;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import security.securityFrame.exception.BusinessLogicException;
import security.securityFrame.exception.ExceptionCode;

import java.util.Optional;

@Service
@AllArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;
    private static final String USER = "USER";
    private static final String PARTNER = "PARTNER";

    public Role findUserRole() {
        Optional<Role> role = roleRepository.findByName(USER);

        if (role.isPresent()) {
            return role.get();
        }

        throw new BusinessLogicException(ExceptionCode.BAD_REQUEST);
    }
}
