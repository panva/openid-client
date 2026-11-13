import { Converter } from 'typedoc'

// The result marker belongs in the emitted declarations for type inference,
// but documentation should show only the underlying response type.
function unwrapResult(type) {
  if (type.type === 'reference') {
    if (type.name === 'WithDecryptedResponse' && type.typeArguments?.length) {
      return unwrapResult(type.typeArguments[0])
    }
    if (type.typeArguments) {
      type.typeArguments = type.typeArguments.map(unwrapResult)
    }
  }
  return type
}

export function load(app) {
  app.converter.on(Converter.EVENT_RESOLVE_BEGIN, (context) => {
    for (const reflection of Object.values(context.project.reflections)) {
      if (reflection.type) reflection.type = unwrapResult(reflection.type)
    }
  })
}
