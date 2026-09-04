(() => {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  document.querySelectorAll('[data-factory-slideshow]').forEach((slideshow) => {
    const images = Array.from(slideshow.querySelectorAll('.factory-img'));
    let activeIndex = 0;
    let autoplayId;

    const showImage = (index) => {
      images.forEach((image, imageIndex) => {
        const isActive = imageIndex === index;
        image.classList.toggle('is-active', isActive);
        image.setAttribute('aria-hidden', String(!isActive));
      });
      activeIndex = index;
    };

    const stopAutoplay = () => {
      window.clearInterval(autoplayId);
      autoplayId = undefined;
    };

    const startAutoplay = () => {
      stopAutoplay();
      if (!reduceMotion.matches && images.length > 1) {
        autoplayId = window.setInterval(() => {
          showImage((activeIndex + 1) % images.length);
        }, 4000);
      }
    };

    slideshow.addEventListener('mouseenter', stopAutoplay);
    slideshow.addEventListener('mouseleave', startAutoplay);
    reduceMotion.addEventListener('change', () => {
      showImage(0);
      startAutoplay();
    });

    showImage(0);
    startAutoplay();
  });
})();
