interface BadgeProps {
  text: string
  variant?: 'default' | 'net' | 'xmod' | string
}

export function Badge({ text, variant = 'default' }: BadgeProps) {
  const cls = ['badge']
  if (variant === 'net' || text.includes('Network')) cls.push('badge-net')
  if (variant === 'xmod') cls.push('badge-xmod')
  return <span className={cls.join(' ')}>{text}</span>
}
