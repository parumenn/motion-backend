// blocksデータをMarkdownテキストに変換する関数 (フロントエンド互換)
export function convertBlocksToMarkdown(blocks: any[], indent: string = ''): string {
  if (!Array.isArray(blocks)) return '';

  let md = '';
  blocks.forEach(b => {
    if (!b || typeof b !== 'object') return; // 想定外の構造をスキップ

    let prefix = '';
    if (b.type === 'h1') prefix = '# ';
    else if (b.type === 'h2') prefix = '## ';
    else if (b.type === 'h3') prefix = '### ';
    else if (b.type === 'todo') prefix = b.checked ? '- [x] ' : '- [ ] ';
    else if (b.type === 'toggle') prefix = '> ';

    let text = '';
    
    // type に応じた文字列の生成とHTMLタグの除去
    if (b.type === 'image') {
      text = `![画像](${b.content || ''})`;
    } else if (b.type === 'page_link') {
      text = `[ページリンク]`;
    } else if (typeof b.content === 'string') {
      text = b.content
        .replace(/<br\s*\/?>/gi, '\n') // <br> を改行に
        .replace(/<[^>]+>/g, '');      // その他のHTMLタグを削除
    } else if (b.content != null) {
      // 想定外の型の場合は文字列化してフォールバック
      text = String(b.content);
    }

    md += `${indent}${prefix}${text}\n`;
    
    // 子要素がある場合は再帰的に処理
    if (Array.isArray(b.children) && b.children.length > 0) {
      md += convertBlocksToMarkdown(b.children, indent + '  ');
    }
  });
  
  return md;
}

