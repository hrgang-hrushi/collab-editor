"use client";

import React from "react";
import PixelGridTransition from "./PixelGridTransition";
import AeyeNavbar from "./AeyeNavbar";
import AeyeHero from "./AeyeHero";
import AeyeBenefitSection from "./AeyeBenefitSection";
import AeyePerformanceSection from "./AeyePerformanceSection";
import AeyeFeatureSection from "./AeyeFeatureSection";
import AeyeHowItWorkSection from "./AeyeHowItWorkSection";
import AeyeInstallationSection from "./AeyeInstallationSection";
import AeyeDocumentSection from "./AeyeDocumentSection";
import AeyeTestimonialSection from "./AeyeTestimonialSection";
import AeyePricingSection from "./AeyePricingSection";
import AeyeChangelogSection from "./AeyeChangelogSection";
import AeyeBlogSection from "./AeyeBlogSection";
import AeyeFaqSection from "./AeyeFaqSection";
import AeyeCtaSection from "./AeyeCtaSection";
import AeyeFooter from "./AeyeFooter";

export default function AeyeLandingPage() {
  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#000000] text-white font-sans selection:bg-[#0055FF]/40 selection:text-white antialiased">
      {/* 0. Entrance Pixel Grid Reveal Animation */}
      <PixelGridTransition color="#0055FF" columns={12} rowMultiplier={3} squareDuration={0.5} maxDelay={0.6} />

      {/* 1. Header & Navigation */}
      <AeyeNavbar onNavigate={scrollTo} />

      {/* 2. Hero Section */}
      <AeyeHero />

      {/* 3. Section 01: [n. 01 / 11 ] > key value */}
      <AeyeBenefitSection />

      {/* 4. Section 02: [n. 02 / 11 ] > Performance */}
      <AeyePerformanceSection />

      {/* 5. Section 03: [n. 03 / 11 ] > core capabilities */}
      <AeyeFeatureSection />

      {/* 6. Section 04: [n. 04 / 11 ] > How It Work */}
      <AeyeHowItWorkSection />

      {/* 7. Section 05: [n. 05 / 11 ] > Installation */}
      <AeyeInstallationSection />

      {/* 8. Section 06: [n. 06 / 11 ] > Document */}
      <AeyeDocumentSection />

      {/* 9. Section 07: [n. 07 / 11 ] > Testimonial */}
      <AeyeTestimonialSection />

      {/* 10. Section 08: [n. 08 / 11 ] > Pricing */}
      <AeyePricingSection />

      {/* 11. Section 09: [n. 09 / 11 ] > Changelogs */}
      <AeyeChangelogSection />

      {/* 12. Section 10: [n. 10 / 11 ] > blog */}
      <AeyeBlogSection />

      {/* 13. Section 11: [n. 11 / 11 ] > FAQs */}
      <AeyeFaqSection />

      {/* 14. Section 12: CTA Workflow Box */}
      <AeyeCtaSection />

      {/* 15. Master Footer & Dispatch */}
      <AeyeFooter />
    </div>
  );
}
