package hello.login.web;

import hello.login.domain.member.Member;
import hello.login.domain.member.MemberRepository;
import hello.login.web.session.SessionManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Slf4j
@Controller
@RequiredArgsConstructor
public class HomeController {

    private final MemberRepository memberRepository;
    private final SessionManager sessionManager;

//    @GetMapping("/")
    public String home() {
        return "home";
    }

   // @GetMapping("/")
    public String homeLogin(@CookieValue(name="memberId", required = false) Long memberId, Model model) { //비로그인 사용자도 들어와야 하니까 required=false임

        if (memberId == null) {
            return "home";
        }

        // 로그인
        Member loginMember = memberRepository.findById(memberId);
        if (loginMember == null) {
            return "home";
        }

        // 성공
        model.addAttribute("member", loginMember);
        return "loginHome";
    }


    //@GetMapping("/")
    public String homeLoginV2(HttpServletRequest request, Model model) {

        // 세션관리자에 저장된 회원 정보 조회
        Member member = (Member) sessionManager.getSession(request);

        // 로그인
        if (member == null) {
            return "home";
        }

        // 성공
        model.addAttribute("member", member);
        return "loginHome";
    }

    @GetMapping("/")
    public String homeLoginV3(HttpServletRequest request, Model model) {

        // 처음 들어온 고객은 세션이 없어야 한다 -> false
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "home";
        }

        Object loginMember = session.getAttribute(SessionConst.LOGIN_MEMBER);
        // 회원데이터가 없으면 홈으로
        if (loginMember == null) {
            return "home";
        }

        // 성공
        model.addAttribute("member", loginMember);
        return "loginHome";
    }

}