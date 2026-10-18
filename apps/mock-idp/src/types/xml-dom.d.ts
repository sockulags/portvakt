/**
 * The DOM interfaces the XML libraries' typings refer to (node-saml, xml-crypto), which assume
 * the global DOM types. The server does not load `lib.dom` (it is not a browser), so only the
 * members Portvakt reads from @xmldom/xmldom nodes are declared here. Never import
 * `@xmldom/xmldom` or `xpath` types directly: their typings pull in `lib.dom`, which would clash.
 */
declare global {
  interface Node {
    readonly nodeType: number;
    readonly nodeName: string;
    readonly localName: string | null;
    readonly namespaceURI: string | null;
    readonly nodeValue: string | null;
    readonly textContent: string | null;
    readonly parentNode: Node | null;
    readonly ownerDocument: Document | null;
    readonly childNodes: NodeListOf<Node>;
    toString(): string;
  }

  interface Element extends Node {
    readonly tagName: string;
    getAttribute(name: string): string | null;
    hasAttribute(name: string): boolean;
    getAttributeNS(namespace: string | null, localName: string): string | null;
    readonly attributes: { readonly length: number; item(index: number): Attr | null };
  }

  interface Attr extends Node {
    readonly name: string;
    readonly value: string;
  }

  interface Document extends Node {
    readonly documentElement: Element | null;
  }

  interface NodeListOf<T> {
    readonly length: number;
    item(index: number): T | null;
    [index: number]: T;
  }
}

export {};
