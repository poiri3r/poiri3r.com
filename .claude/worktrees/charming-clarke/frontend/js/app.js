document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.querySelector(".nav");
  const holoCard = document.querySelector(".js-holo-card");

  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      nav.classList.toggle("open");
    });
  }

  // 네비게이션 스크롤 이동 + active 표시
  const navLinks = document.querySelectorAll(".nav-list a[href^='#']");
  const sections = document.querySelectorAll("section[id]");

  navLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute("href"));
      if (target) {
        target.scrollIntoView({ behavior: "smooth" });
      }
      if (nav.classList.contains("open")) {
        nav.classList.remove("open");
      }
    });
  });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        navLinks.forEach(link => link.classList.remove("active"));
        const active = document.querySelector(`.nav-list a[href='#${entry.target.id}']`);
        if (active) active.classList.add("active");
      }
    });
  }, { threshold: 0.4 });

  sections.forEach(section => observer.observe(section));

  if (!holoCard) return;

  const maxTilt = 10;
  const overlay = document.createElement("div");
  overlay.className = "holo-overlay";
  document.body.appendChild(overlay);

  let isZoomed = false;

  const applyPointer = (clientX, clientY) => {
    const rect = holoCard.getBoundingClientRect();
    const x = (clientX - rect.left) / rect.width;
    const y = (clientY - rect.top) / rect.height;
    const clampX = Math.min(Math.max(x, 0), 1);
    const clampY = Math.min(Math.max(y, 0), 1);

    const mx = `${(clampX * 100).toFixed(2)}%`;
    const my = `${(clampY * 100).toFixed(2)}%`;
    const ry = `${((clampX - 0.5) * (maxTilt * 2)).toFixed(2)}deg`;
    const rx = `${((0.5 - clampY) * (maxTilt * 2)).toFixed(2)}deg`;
    const dx = clampX - 0.5;
    const dy = clampY - 0.5;
    const dist = Math.min(Math.sqrt(dx * dx + dy * dy) / 0.7071, 1);

    holoCard.style.setProperty("--mx", mx);
    holoCard.style.setProperty("--my", my);
    holoCard.style.setProperty("--ry", ry);
    holoCard.style.setProperty("--rx", rx);
    holoCard.style.setProperty("--hyp", dist.toFixed(3));
  };

  const resetPointer = () => {
    holoCard.style.setProperty("--mx", "50%");
    holoCard.style.setProperty("--my", "50%");
    holoCard.style.setProperty("--ry", "0deg");
    holoCard.style.setProperty("--rx", "0deg");
    holoCard.style.setProperty("--hyp", "0");
  };

  const setCenteredOffset = () => {
    const rect = holoCard.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const tx = window.innerWidth / 2 - cx;
    const ty = window.innerHeight / 2 - cy;

    holoCard.style.setProperty("--tx", `${tx.toFixed(2)}px`);
    holoCard.style.setProperty("--ty", `${ty.toFixed(2)}px`);
  };

  const openCard = () => {
    holoCard.classList.remove("is-zoomed");
    holoCard.style.setProperty("--tx", "0px");
    holoCard.style.setProperty("--ty", "0px");
    holoCard.style.removeProperty("--scale");
    setCenteredOffset();
    overlay.classList.add("show");
    holoCard.classList.add("is-opening");
    isZoomed = true;

    window.setTimeout(() => {
      holoCard.classList.remove("is-opening");
      holoCard.classList.add("is-zoomed");
    }, 540);
  };

  const closeCard = () => {
    overlay.classList.remove("show");
    holoCard.classList.remove("is-zoomed");
    holoCard.classList.remove("is-opening");
    holoCard.style.setProperty("--tx", "0px");
    holoCard.style.setProperty("--ty", "0px");
    holoCard.style.setProperty("--rx", "0deg");
    holoCard.style.setProperty("--ry", "0deg");
    holoCard.style.setProperty("--scale", "1");
    isZoomed = false;

    setTimeout(() => {
      holoCard.style.removeProperty("--scale");
    }, 520);
  };

  holoCard.addEventListener("pointermove", (event) => {
    applyPointer(event.clientX, event.clientY);
  });

  holoCard.addEventListener("pointerleave", () => {
    if (!isZoomed) {
      resetPointer();
    }
  });

  document.addEventListener("pointermove", (event) => {
    if (isZoomed) {
      applyPointer(event.clientX, event.clientY);
    }
  });

  holoCard.addEventListener("click", (event) => {
    event.preventDefault();
    if (isZoomed) {
      closeCard();
    } else {
      openCard();
    }
  });

  overlay.addEventListener("click", () => {
    closeCard();
  });

  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeCard();
    }
  });

  window.addEventListener("resize", () => {
    if (isZoomed) {
      setCenteredOffset();
    }
  });
});
