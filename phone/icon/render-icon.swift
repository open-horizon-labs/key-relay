// Renders the KeyRelay app icon (1024 x 1024, opaque) with Core Graphics.
// Usage: swift render-icon.swift <output.png> [light|dark|tinted]
// Original artwork: a key whose bow emits relay waves. No SF Symbols (not licensed for icons).
import CoreGraphics
import Foundation
import ImageIO

let args = CommandLine.arguments
let out = URL(fileURLWithPath: args.count > 1 ? args[1] : "AppIcon.png")
let variant = args.count > 2 ? args[2] : "light"
let size = 1024
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                    space: cs, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!  // opaque, as App Store icons require
func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: a)
}

// Background
let s = CGFloat(size)
switch variant {
case "tinted":
    ctx.setFillColor(rgb(0x000000)); ctx.fill(CGRect(x: 0, y: 0, width: s, height: s))
case "dark":
    let g = CGGradient(colorsSpace: cs, colors: [rgb(0x0B1220), rgb(0x10243A)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(g, start: CGPoint(x: 0, y: s), end: CGPoint(x: s, y: 0), options: [])
default:
    let g = CGGradient(colorsSpace: cs, colors: [rgb(0x312E81), rgb(0x0E7490)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(g, start: CGPoint(x: 0, y: s), end: CGPoint(x: s, y: 0), options: [])
    // soft light from the top
    let glow = CGGradient(colorsSpace: cs, colors: [rgb(0xFFFFFF, 0.18), rgb(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glow, startCenter: CGPoint(x: s * 0.35, y: s * 0.85), startRadius: 0,
                           endCenter: CGPoint(x: s * 0.35, y: s * 0.85), endRadius: s * 0.75, options: [])
}

let ink: CGColor = variant == "dark" ? rgb(0xE0F2FE) : rgb(0xFFFFFF)
let accent: CGColor = variant == "dark" ? rgb(0x67E8F9) : (variant == "tinted" ? rgb(0xFFFFFF, 0.75) : rgb(0x67E8F9))

// Key, rotated 45°, bow at upper right, shaft running to lower left.
// Core Graphics has y pointing up, so a positive rotation turns +x toward the upper right.
let keyCenter = CGPoint(x: s * 0.42, y: s * 0.42)
ctx.saveGState()
ctx.translateBy(x: keyCenter.x, y: keyCenter.y)
ctx.rotate(by: .pi / 4)
let bowCenter = CGPoint(x: 150, y: 0)
let bowOuter: CGFloat = 165, bowInner: CGFloat = 72
let bow = CGMutablePath()
bow.addEllipse(in: CGRect(x: bowCenter.x - bowOuter, y: -bowOuter, width: bowOuter * 2, height: bowOuter * 2))
bow.addEllipse(in: CGRect(x: bowCenter.x - bowInner, y: -bowInner, width: bowInner * 2, height: bowInner * 2))
ctx.addPath(bow)
ctx.setFillColor(ink)
ctx.fillPath(using: .evenOdd)
// shaft
let shaftH: CGFloat = 74
let shaft = CGPath(roundedRect: CGRect(x: -318, y: -shaftH / 2, width: 328, height: shaftH),
                   cornerWidth: 16, cornerHeight: 16, transform: nil)
ctx.addPath(shaft); ctx.fillPath()
// teeth
for (x, h) in [(-318.0, 112.0), (-218.0, 84.0)] as [(CGFloat, CGFloat)] {
    let tooth = CGPath(roundedRect: CGRect(x: x, y: -shaftH / 2 - h + 20, width: 66, height: h),
                       cornerWidth: 18, cornerHeight: 18, transform: nil)
    ctx.addPath(tooth); ctx.fillPath()
}
ctx.restoreGState()

// Relay waves, centred on the bow, opening toward the upper right.
let bowWorld = CGPoint(x: keyCenter.x + 150 * cos(.pi / 4), y: keyCenter.y + 150 * sin(.pi / 4))
ctx.setStrokeColor(accent)
ctx.setLineCap(.round)
for (i, r) in [235.0, 305.0, 375.0].enumerated() {
    ctx.setLineWidth(40 - CGFloat(i) * 4)
    ctx.setAlpha(1 - CGFloat(i) * 0.25)
    ctx.addArc(center: bowWorld, radius: CGFloat(r), startAngle: .pi / 4 - 0.5, endAngle: .pi / 4 + 0.5, clockwise: false)
    ctx.strokePath()
}
ctx.setAlpha(1)

let image = ctx.makeImage()!
// Write through ImageIO so the PNG stays RGB without an alpha channel.
let dest = CGImageDestinationCreateWithURL(out as CFURL, "public.png" as CFString, 1, nil)!
CGImageDestinationAddImage(dest, image, nil)
precondition(CGImageDestinationFinalize(dest), "PNG write failed")
print("wrote \(out.path) (\(variant))")
