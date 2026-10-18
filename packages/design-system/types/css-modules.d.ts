// CSS Modules as the bundler (Vite) provides them: a map from class name to generated class name.
declare module "*.module.css" {
  const classes: Readonly<Record<string, string>>;
  export default classes;
}
