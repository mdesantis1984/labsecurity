import { Component, ElementRef } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-inline',
  template: `
    <!-- ruleid: labsec.angular.inner-html-binding -->
    <div [innerHTML]="html"></div>
    <!-- ok: labsec.angular.inner-html-binding -->
    <div [textContent]="text"></div>
    <!-- ok: labsec.angular.inner-html-binding -->
    <p>{{ text }}</p>
  `,
})
export class InlineComponent {
  html = '';
  text = '';
}

export class DomExamples {
  constructor(private readonly host: ElementRef, private readonly sanitizer: DomSanitizer) {}

  positives(value: string, el: HTMLElement): void {
    // ruleid: labsec.typescript.dom-html-assignment
    this.host.nativeElement.innerHTML = value;
    // ruleid: labsec.typescript.dom-html-assignment
    el.innerHTML = '<b>' + value + '</b>';
    // ruleid: labsec.typescript.dom-html-assignment
    el.innerHTML += value;
    // ruleid: labsec.typescript.dom-html-assignment
    el.outerHTML = value;
    // ruleid: labsec.typescript.dom-html-assignment
    el.insertAdjacentHTML('beforeend', value);

    // ruleid: labsec.angular.bypass-security-trust
    this.sanitizer.bypassSecurityTrustHtml(value);
    // ruleid: labsec.angular.bypass-security-trust
    this.sanitizer.bypassSecurityTrustScript(value);
    // ruleid: labsec.angular.bypass-security-trust
    this.sanitizer.bypassSecurityTrustStyle(value);
    // ruleid: labsec.angular.bypass-security-trust
    this.sanitizer.bypassSecurityTrustUrl(value);
    // ruleid: labsec.angular.bypass-security-trust
    this.sanitizer.bypassSecurityTrustResourceUrl(value);

    // ruleid: labsec.typescript.document-write
    document.write(value);
    // ruleid: labsec.typescript.document-write
    document.writeln(value);

    // ruleid: labsec.typescript.dynamic-code-execution
    eval(value);
    // ruleid: labsec.typescript.dynamic-code-execution
    const fn = new Function('a', 'return a + ' + value);
    // ruleid: labsec.typescript.dynamic-code-execution
    setTimeout('doWork(' + value + ')', 100);
    // ruleid: labsec.typescript.dynamic-code-execution
    setInterval('tick()', 1000);
    // ruleid: labsec.typescript.dynamic-code-execution
    setTimeout(`run(${value})`, 100);
  }

  negatives(value: string, el: HTMLElement): void {
    // ok: labsec.typescript.dom-html-assignment
    el.textContent = value;
    // ok: labsec.typescript.dom-html-assignment
    el.innerText = value;
    // ok: labsec.typescript.dom-html-assignment
    el.innerHTML = '';
    // ok: labsec.typescript.dom-html-assignment
    el.insertAdjacentText('beforeend', value);
    // ok: labsec.angular.bypass-security-trust
    this.sanitizer.sanitize(1, value);
    // ok: labsec.typescript.document-write
    document.createElement('div');
    // ok: labsec.typescript.document-write
    document.title = value;
    // ok: labsec.typescript.dynamic-code-execution
    setTimeout(() => this.negatives(value, el), 100);
    // ok: labsec.typescript.dynamic-code-execution
    setInterval(this.tick, 1000);
    // ok: labsec.typescript.dynamic-code-execution
    JSON.parse(value);
  }

  tick(): void {}
}
