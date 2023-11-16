package hello.login.web.login;

import hello.login.domain.login.LoginService;
import hello.login.domain.member.Member;
import hello.login.web.session.SessionConst;
import hello.login.web.session.SessionManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.*;
import javax.validation.Valid;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;
    private final SessionManager sessionManager;

    @GetMapping("/login")
    public String LoginForm(@ModelAttribute("loginForm") LoginForm form) {
        return "login/loginForm";
    }

    //    @PostMapping("/login")
    public String login(@Valid @ModelAttribute LoginForm form,
                        BindingResult bindingResult,
                        HttpServletResponse response) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }
        //로그인 성공 처리

        //쿠키에 시간 정보를 주지 않으면 세션 쿠키(브라우저 종료시 모두 종료)
        Cookie idCookie = new Cookie("memberId", String.valueOf(loginMember.getId()));
        //쿠키 이름 : memberId | 값: 회원의 id | 역할 : 웹 브라우저가 종료전까지 회원의 id를 서버에 보내준다.
        response.addCookie(idCookie);

        return "redirect:/";
    }

    //        @PostMapping("/login")
    public String loginV2(@Valid @ModelAttribute LoginForm form,
                          BindingResult bindingResult,
                          HttpServletResponse response) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }
        //로그인 성공 처리

        //세션 관리자를 통해 세션을 생성하고, 회원 데이터 보관
        sessionManager.createSession(loginMember, response);

        return "redirect:/";
    }

    @PostMapping("/login")
    public String loginV3(@Valid @ModelAttribute LoginForm form,
                          BindingResult bindingResult,
                          HttpServletRequest request) {
        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }
        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }
        //로그인 성공 처리

        //세션이 있으면 있는 세션을 반환, 없느면 신규 세션을 생성
        //getSession()의 default값 : ture
        //falue로 설정할 경우 있는 세션은 반환 없으면 생성 안함.
        HttpSession session = request.getSession();
        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
        return "redirect:/";
    }

    //    @PostMapping("/logout")
    public String logout(HttpServletResponse response) {
        expireCookie(response, "memberId");
        return "redirect:/";
    }

//    @PostMapping("/logout")
    public String logoutV2(HttpServletRequest request) {
        sessionManager.expire(request);
        return "redirect:/";
    }

    @PostMapping("/logout")
    public String logoutV3(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate(); //해당 세션의 모든 값이 날라가도록
        }
        return "redirect:/";
    }

    private static void expireCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
