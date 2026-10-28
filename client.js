/**
 * 代码安全防御规则评审判官 · 主面板（Client 半边）。
 *
 * 注册两处：
 *   1. `sidebar.panellist`：id `security-judge`、order 21 的侧栏入口（盾牌 + 放大镜图标）；
 *   2. `main`：key `security-judge` 的整页面板。
 *
 * 数据只走 Host 注册的两个同源接口（CONTRACT §1 是唯一权威）：
 *   GET  /dsh-security-judge/api/state   完整状态（authority / settings / stats / sessions / catalog）
 *   POST /dsh-security-judge/api/action  { action, payload }；成功时尽量附带最新 state
 *
 * 样式只用宿主主题 token（--dsw-alias-* / --dsw-radius-*），不引宿主组件库、不读宿主 DOM、
 * 不往 document.body 追加任何节点。界面文案为简体中文。
 */
window.__ModuleLoader__.load({
  id: 'dsh-security-judge',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useCallback, useEffect, useMemo, useRef, useState } = React

    /** 主面板 key / 侧栏面板 id，两处必须一致。 */
    const PANEL_ID = 'security-judge'
    /** 插件 HTTP 前缀。 */
    const API = '/dsh-security-judge/api'
    /** 轮询间隔：契约 §4.5 要求 2.5 秒。 */
    const POLL_MS = 2500
    /** 单组列表最多渲染多少条。 */
    const LIST_LIMIT = 24

    /** 契约缺字段时的兜底文案（与 CONTRACT §1 / §5 一致）。 */
    const DEFAULT_CHARTER = '本评审判官权限低于用户最高权限，只用于审核评审会话是否按代码安全防御规则做了代码安全防御架构；不能修改代码、不能修改配置、不能代替用户做决定。'
    const DEFAULT_SCOPE = '代码安全防御规则与架构的评审（只读审查 + 完成门禁）'

    /** 评审模式：advisory / remind / block。 */
    const MODE_INFO = {
      advisory: { text: '只提示', short: '只提示', hint: '记录评审结论并提示，不打断会话。' },
      remind: { text: '提醒', short: '提醒', hint: '评审不合格时向代码会话注入提醒，要求重做。' },
      block: { text: '阻断', short: '阻断', hint: '评审不合格的代码任务不能算完成；不合格必须重做，直到合格（需要授权）。' },
    }

    /**
     * 评审状态徽章（与 Host 语义一致：未通过 = 不合格）：
     *   pending / failed 都属于「不合格」，必须重做；只有 passed 才是合格。
     */
    const REVIEW_INFO = {
      none: { text: '未评审', tone: 'muted' },
      pending: { text: '待评审', tone: 'warn' },
      passed: { text: '合格', tone: 'success' },
      failed: { text: '不合格', tone: 'error' },
      waived: { text: '已豁免', tone: 'info' },
      na: { text: '不涉及', tone: 'muted' },
    }

    const VERDICT_TEXT = {
      pass: '合格',
      fail: '不合格',
      pending: '待评审',
      none: '未评审',
      na: '不涉及',
    }

    /** 规则等级：L1 强制 / L2 基线 / L3 建议。 */
    const LEVEL_INFO = {
      L1: { text: 'L1 强制', tone: 'error', hint: '强制项，Host 不允许豁免。' },
      L2: { text: 'L2 基线', tone: 'warn', hint: '基线项，可按登记理由豁免。' },
      L3: { text: 'L3 建议', tone: 'muted', hint: '建议项，可按登记理由豁免。' },
    }

    /** 架构冲突严重度：hard 红、overlap 橙、tension 黄（用 warn 的深/浅两档 + 虚线区分）。 */
    const SEVERITY_INFO = {
      hard: {
        text: '硬冲突',
        color: 'var(--dsw-alias-state-error-primary)',
        border: 'var(--dsw-alias-state-error-primary)',
        background: 'var(--dsw-alias-bg-layer-2)',
        dashed: false,
      },
      overlap: {
        text: '重叠',
        color: 'var(--dsw-alias-state-warn-primary)',
        border: 'var(--dsw-alias-state-warn-primary)',
        background: 'var(--dsw-alias-state-warn-tertiary)',
        dashed: false,
      },
      tension: {
        text: '张力',
        color: 'var(--dsw-alias-state-warn-label)',
        border: 'var(--dsw-alias-state-warn-secondary)',
        background: 'var(--dsw-alias-state-warn-tertiary)',
        dashed: true,
      },
    }

    const SEVERITY_HINT = {
      hard: '直接矛盾：两种架构不能按原样同时实施，必须择一或改写。',
      overlap: '职责重叠：两种架构在管同一件事，需要明确主责，避免漏检。',
      tension: '取舍张力：可以共存，但实现上要做权衡并记录理由。',
    }

    const PROJECT_KIND_LABEL = {
      android: 'Android 应用',
      server: '服务端',
      web: 'Web 前端',
      desktop: '桌面应用',
      iot: '物联网 / 嵌入式',
      cli: '命令行工具',
      mixed: '混合项目',
      unknown: '类型未判定',
    }

    const STATUS_LABEL = {
      running: '运行中',
      idle: '空闲',
      unknown: '状态未知',
    }

    /** 错误码 → 可执行的中文提示（契约 §1 错误码表）。 */
    const ERROR_HINTS = {
      'authority-required': '这个操作需要先获得用户授权。',
      'not-code-session': '该会话不是代码会话，不能评审或提醒。',
      'unknown-session': '找不到这个会话，可能已经结束，请刷新。',
      'unknown-action': 'Host 不认识这个操作，插件两半版本可能不一致。',
      'bad-payload': '请求参数不合法，请刷新后重试。',
      'l1-not-waivable': 'L1 强制项不能豁免。',
      'confirm-required': '这个操作需要二次确认，请重新执行并确认。',
      'internal-error': '插件内部出错，请重试；多次失败请反馈日志。',
    }

    const TONE_COLOR = {
      success: 'var(--dsw-alias-state-success-primary)',
      warn: 'var(--dsw-alias-state-warn-primary)',
      error: 'var(--dsw-alias-state-error-primary)',
      info: 'var(--dsw-alias-brand-primary)',
      muted: 'var(--dsw-alias-label-secondary)',
    }

    // ============================================================
    // 样式：只用主题 token，卡片 / 圆角 / 间距对齐 system-guard 与宿主设置页
    // ============================================================
    const S = {
      // 面板骨架：宿主 main 区是 flex 列，这里撑满并自己管滚动。
      panel: {
        height: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        minHeight: 0,
        background: 'var(--dsw-alias-bg-base)',
        color: 'var(--dsw-alias-label-primary)',
      },
      scroller: {
        flex: '1 1 auto',
        minHeight: 0,
        overflowY: 'auto',
        overflowX: 'hidden',
        boxSizing: 'border-box',
        paddingTop: 'calc(28px + var(--dsh-frame-top-clearance, 0px))',
        paddingBottom: '64px',
        paddingLeft: 'max(clamp(16px, 4vw, 48px), calc((100% - 960px) / 2))',
        paddingRight: 'max(clamp(16px, 4vw, 48px), calc((100% - 960px) / 2))',
      },
      stack: {
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
        width: '100%',
        maxWidth: '960px',
        margin: '0 auto',
        fontSize: '13px',
        lineHeight: '1.6',
      },
      header: {
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: '16px',
        flexWrap: 'wrap',
      },
      headerText: { display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 },
      title: { fontSize: '20px', fontWeight: 600, margin: 0, lineHeight: '1.4' },
      subtitle: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      hint: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      tiny: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      card: {
        background: 'var(--dsw-alias-bg-layer-1)',
        // 黑色边框：浅色主题是黑框、深色主题自动变成白框（同一个 token，跟随模式）。
        border: '1.5px solid var(--dsw-alias-label-primary)',
        borderRadius: '12px',
        padding: '16px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      },
      cardHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' },
      cardTitle: { fontSize: '14px', fontWeight: 600, margin: 0 },
      cardExtra: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px' },
      charter: {
        margin: 0,
        fontSize: '13px',
        fontWeight: 600,
        color: 'var(--dsw-alias-state-warn-label)',
        border: '1px solid var(--dsw-alias-state-warn-primary)',
        borderRadius: '10px',
        padding: '10px 12px',
        background: 'var(--dsw-alias-bg-layer-2)',
        lineHeight: '1.6',
      },
      actionRow: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
      button: {
        background: 'var(--dsw-alias-label-primary)',
        color: 'var(--dsw-alias-bg-base)',
        border: 'none',
        borderRadius: '8px',
        padding: '9px 18px',
        fontSize: '14px',
        fontWeight: 600,
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonSecondary: {
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-label-primary)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '6px 14px',
        fontSize: '12px',
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonDanger: {
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-state-error-primary)',
        border: '1px solid var(--dsw-alias-state-error-primary)',
        borderRadius: '8px',
        padding: '6px 14px',
        fontSize: '12px',
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      buttonDisabled: { opacity: 0.5, cursor: 'default' },
      linkButton: {
        background: 'transparent',
        border: 'none',
        padding: '0 2px',
        color: 'var(--dsw-alias-brand-primary)',
        fontSize: '12px',
        cursor: 'pointer',
        fontFamily: 'inherit',
      },
      input: {
        width: '120px',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-bg-base)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '6px 10px',
        color: 'var(--dsw-alias-label-primary)',
        fontSize: '13px',
        fontFamily: 'inherit',
      },
      inputNarrow: {
        width: '84px',
        boxSizing: 'border-box',
        background: 'var(--dsw-alias-bg-base)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '6px 10px',
        color: 'var(--dsw-alias-label-primary)',
        fontSize: '13px',
        fontFamily: 'inherit',
      },
      textarea: {
        width: '100%',
        minHeight: '56px',
        boxSizing: 'border-box',
        resize: 'vertical',
        background: 'var(--dsw-alias-bg-base)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '8px 10px',
        color: 'var(--dsw-alias-label-primary)',
        fontSize: '13px',
        fontFamily: 'inherit',
        lineHeight: '1.6',
      },
      badge: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '1px 9px',
        borderRadius: '999px',
        fontSize: '12px',
        fontWeight: 600,
        border: '1px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-layer-2)',
        whiteSpace: 'nowrap',
      },
      badgePlain: {
        fontSize: '11px',
        color: 'var(--dsw-alias-label-secondary)',
        whiteSpace: 'nowrap',
      },
      chip: {
        display: 'inline-flex',
        alignItems: 'center',
        padding: '1px 8px',
        borderRadius: '999px',
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--dsw-alias-brand-primary)',
        border: '1px solid var(--dsw-alias-brand-primary)',
        background: 'transparent',
        whiteSpace: 'nowrap',
      },
      chipMuted: {
        display: 'inline-flex',
        alignItems: 'center',
        padding: '1px 8px',
        borderRadius: '999px',
        fontSize: '11px',
        color: 'var(--dsw-alias-label-secondary)',
        border: '1px solid var(--dsw-alias-border-l2)',
        background: 'transparent',
        whiteSpace: 'nowrap',
      },
      chips: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' },
      statGrid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(126px, 1fr))',
        gap: '10px',
      },
      statTile: {
        display: 'flex',
        flexDirection: 'column',
        gap: '2px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '10px',
        background: 'var(--dsw-alias-bg-layer-2)',
        padding: '10px 12px',
        minWidth: 0,
      },
      statValue: { fontSize: '22px', fontWeight: 700, lineHeight: '1.2' },
      statLabel: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      sessionRow: {
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '10px',
        background: 'var(--dsw-alias-bg-layer-2)',
        overflow: 'hidden',
      },
      sessionRowOpen: { borderColor: 'var(--dsw-alias-brand-primary)' },
      sessionHead: {
        display: 'flex',
        alignItems: 'flex-start',
        gap: '10px',
        padding: '10px 12px',
        cursor: 'pointer',
      },
      statusDot: {
        flex: 'none',
        width: '9px',
        height: '9px',
        marginTop: '7px',
        boxSizing: 'border-box',
        borderRadius: '50%',
        boxShadow: '0 0 0 2px var(--dsw-alias-bg-layer-2)',
      },
      sessionMain: { display: 'flex', flexDirection: 'column', gap: '3px', flex: '1 1 auto', minWidth: 0 },
      sessionTitleRow: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
      sessionTitle: { fontSize: '13px', fontWeight: 600, wordBreak: 'break-word' },
      sessionMeta: { display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap', fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      sessionBadges: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', flex: 'none' },
      sessionCaret: { flex: 'none', color: 'var(--dsw-alias-brand-primary)', fontWeight: 700, fontSize: '12px', marginTop: '2px' },
      sessionBody: {
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
        padding: '4px 12px 12px 12px',
        borderTop: '1px solid var(--dsw-alias-border-l1)',
      },
      subCard: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '10px',
        background: 'var(--dsw-alias-bg-layer-1)',
        padding: '10px 12px',
      },
      subHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', flexWrap: 'wrap' },
      subTitle: { fontSize: '13px', fontWeight: 600, margin: 0 },
      subExtra: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      subBody: { display: 'flex', flexDirection: 'column', gap: '8px' },
      archCard: {
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        background: 'var(--dsw-alias-bg-layer-2)',
        padding: '8px 10px',
      },
      archHead: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap' },
      archName: { fontSize: '13px', fontWeight: 600 },
      archBadges: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' },
      archText: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      archMeta: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      ruleGroup: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '10px',
        padding: '8px 12px',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      ruleHeadButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        width: '100%',
        boxSizing: 'border-box',
        background: 'transparent',
        border: 'none',
        padding: 0,
        margin: 0,
        cursor: 'pointer',
        color: 'var(--dsw-alias-label-primary)',
        font: 'inherit',
        textAlign: 'left',
      },
      ruleHeadText: { display: 'flex', alignItems: 'baseline', gap: '10px', flex: '1 1 auto', minWidth: 0, flexWrap: 'wrap' },
      ruleGroupTitle: { fontSize: '13px', fontWeight: 600 },
      ruleGroupMeta: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px' },
      ruleBody: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        maxHeight: '420px',
        overflowY: 'auto',
        overflowX: 'hidden',
        paddingRight: '4px',
      },
      ruleRow: {
        display: 'flex',
        flexDirection: 'column',
        gap: '3px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '8px',
        background: 'var(--dsw-alias-bg-layer-1)',
        padding: '7px 10px',
      },
      ruleRowHead: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
      ruleId: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '12px', fontWeight: 600 },
      ruleTitle: { fontSize: '12px', flex: '1 1 auto', minWidth: 0, wordBreak: 'break-word' },
      ruleMeta: { fontSize: '11px', color: 'var(--dsw-alias-label-secondary)' },
      ruleCriteria: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      conflictItem: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '10px',
        background: 'var(--dsw-alias-bg-layer-2)',
        padding: '9px 12px',
        boxSizing: 'border-box',
      },
      conflictHead: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
      conflictTitle: { fontSize: '13px', fontWeight: 600, flex: '1 1 auto', minWidth: 0, wordBreak: 'break-word' },
      conflictMeta: {
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
        fontSize: '11px',
        color: 'var(--dsw-alias-label-secondary)',
        flex: 'none',
      },
      conflictDetail: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
      conflictResolution: {
        margin: 0,
        fontSize: '12px',
        border: '1px dashed var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        padding: '8px 10px',
        background: 'var(--dsw-alias-bg-base)',
        color: 'var(--dsw-alias-label-primary)',
      },
      ackBar: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        border: '1px solid var(--dsw-alias-brand-primary)',
        borderRadius: '10px',
        padding: '10px 12px',
        background: 'var(--dsw-alias-bg-base)',
      },
      progressGrid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(108px, 1fr))',
        gap: '8px',
      },
      progressCell: {
        display: 'flex',
        flexDirection: 'column',
        gap: '2px',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: '8px',
        background: 'var(--dsw-alias-bg-layer-2)',
        padding: '7px 10px',
      },
      progressCellValue: { fontSize: '16px', fontWeight: 700, lineHeight: '1.3' },
      progressCellLabel: { fontSize: '11px', color: 'var(--dsw-alias-label-secondary)' },
      progressTrack: {
        height: '6px',
        borderRadius: '999px',
        background: 'var(--dsw-alias-bg-layer-2)',
        overflow: 'hidden',
      },
      progressFill: {
        height: '100%',
        borderRadius: '999px',
        background: 'var(--dsw-alias-brand-primary)',
        transition: 'width 240ms ease',
      },
      list: { display: 'flex', flexDirection: 'column', gap: '4px', margin: 0, padding: 0, listStyle: 'none' },
      listItem: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-word', margin: 0 },
      mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '11px', wordBreak: 'break-all' },
      empty: { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px', margin: 0 },
      error: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px', margin: 0 },
      ok: { color: 'var(--dsw-alias-state-success-primary)', fontSize: '12px', margin: 0 },
      banner: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        flexWrap: 'wrap',
        borderRadius: '10px',
        padding: '10px 12px',
        fontSize: '12px',
        border: '1px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-layer-2)',
      },
      bannerError: {
        borderColor: 'var(--dsw-alias-state-error-primary)',
        color: 'var(--dsw-alias-state-error-primary)',
      },
      bannerOk: {
        borderColor: 'var(--dsw-alias-state-success-primary)',
        color: 'var(--dsw-alias-state-success-primary)',
      },
      divider: { height: '1px', background: 'var(--dsw-alias-border-l1)', border: 'none', margin: 0 },
      field: { display: 'flex', flexDirection: 'column', gap: '6px' },
      fieldLabel: { fontSize: '12px', fontWeight: 600 },
      fieldHint: { fontSize: '11px', color: 'var(--dsw-alias-label-secondary)', margin: 0 },
      settingsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' },
      segRow: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' },
      segButton: {
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-label-primary)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '999px',
        padding: '4px 12px',
        fontSize: '12px',
        fontFamily: 'inherit',
        cursor: 'pointer',
        lineHeight: '1.5',
      },
      segActive: {
        background: 'var(--dsw-alias-label-primary)',
        color: 'var(--dsw-alias-bg-base)',
        borderColor: 'var(--dsw-alias-label-primary)',
        fontWeight: 600,
      },
      kv: {
        display: 'grid',
        gridTemplateColumns: 'auto 1fr',
        gap: '4px 14px',
        fontSize: '12px',
        alignItems: 'baseline',
      },
      kvKey: { color: 'var(--dsw-alias-label-secondary)' },
      kvValue: { minWidth: 0, wordBreak: 'break-word' },
      confirmBar: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        border: '1px solid var(--dsw-alias-state-warn-primary)',
        borderRadius: '10px',
        padding: '10px 12px',
        background: 'var(--dsw-alias-bg-base)',
      },
      confirmBarDanger: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        border: '1px solid var(--dsw-alias-state-error-primary)',
        borderRadius: '10px',
        padding: '10px 12px',
        background: 'var(--dsw-alias-bg-base)',
      },
      confirmText: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-label-primary)' },
      confirmDangerText: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-state-error-primary)' },
      footer: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        borderTop: '1px solid var(--dsw-alias-border-l1)',
        paddingTop: '14px',
      },
      footerText: { margin: 0, fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' },
    }

    // ============================================================
    // 纯函数工具
    // ============================================================
    function isObj(value) {
      return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    }

    function arr(value) {
      return Array.isArray(value) ? value : []
    }

    function num(value) {
      const n = Number(value)
      return Number.isFinite(n) ? n : 0
    }

    function text(value, fallback) {
      if (typeof value === 'string') return value.trim() ? value : (fallback === undefined ? '' : fallback)
      if (typeof value === 'number' && Number.isFinite(value)) return String(value)
      return fallback === undefined ? '' : fallback
    }

    function messageOf(error) {
      if (!error) return '操作失败。'
      if (typeof error === 'string') return error
      if (typeof error.message === 'string' && error.message.trim()) return error.message
      return '操作失败。'
    }

    function clamp(n, min, max) {
      return Math.min(max, Math.max(min, n))
    }

    function clampInt(value, min, max, fallback) {
      if (typeof value === 'string' && value.trim() === '') return fallback
      if (value === null || value === undefined || value === '') return fallback
      const n = Number(value)
      if (!Number.isFinite(n)) return fallback
      return clamp(Math.round(n), min, max)
    }

    function numberOrDefault(value, fallback) {
      if (value === null || value === undefined || value === '') return fallback
      return Number.isFinite(Number(value)) ? value : fallback
    }

    function formatTime(timestamp) {
      const n = Number(timestamp)
      if (!Number.isFinite(n) || n <= 0) return '从未'
      try {
        return new Date(n).toLocaleString('zh-CN', { hour12: false })
      } catch (error) {
        return '时间未知'
      }
    }

    function formatRelative(timestamp) {
      const n = Number(timestamp)
      if (!Number.isFinite(n) || n <= 0) return '未知'
      const diff = Date.now() - n
      if (diff < 0) return formatTime(n)
      if (diff < 60000) return '刚刚'
      if (diff < 3600000) return `${Math.floor(diff / 60000)} 分钟前`
      if (diff < 86400000) return `${Math.floor(diff / 3600000)} 小时前`
      return formatTime(n)
    }

    function formatMs(ms) {
      const n = Number(ms)
      if (!Number.isFinite(n) || n <= 0) return '未设置'
      if (n < 1000) return `${Math.round(n)} 毫秒`
      return `${(n / 1000).toFixed(n % 1000 === 0 ? 0 : 1)} 秒`
    }

    function reviewInfo(state) {
      return REVIEW_INFO[text(state)] || REVIEW_INFO.none
    }

    function levelInfo(level) {
      return LEVEL_INFO[text(level)] || { text: text(level, '等级未知'), tone: 'muted', hint: '' }
    }

    function modeInfo(mode) {
      return MODE_INFO[text(mode)] || MODE_INFO.advisory
    }

    function severityInfo(severity) {
      return SEVERITY_INFO[text(severity)] || {
        text: text(severity, '未知'),
        color: TONE_COLOR.muted,
        border: 'var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-layer-2)',
        dashed: false,
      }
    }

    function statusColor(status) {
      if (text(status) === 'running') return 'var(--dsw-alias-state-success-primary)'
      if (text(status) === 'idle') return 'var(--dsw-alias-label-secondary)'
      return 'var(--dsw-alias-label-tertiary)'
    }

    function archCountText(count) {
      const n = Math.max(0, Math.round(num(count)))
      if (n <= 0) return '需要架构：未判定'
      if (n === 1) return '需要 1 种架构'
      if (n === 2) return '需要 2 种架构'
      return `需要多种架构（${n} 种）`
    }

    function projectKindText(kind) {
      return PROJECT_KIND_LABEL[text(kind)] || PROJECT_KIND_LABEL.unknown
    }

    /** 会话实际上的评审状态：state 为 none 而 verdict 为 na 时按「不涉及」显示。 */
    function sessionReviewState(review) {
      const state = text(review && review.state, 'none')
      const verdict = text(review && review.verdict, 'none')
      if (state === 'none' && verdict === 'na') return 'na'
      return REVIEW_INFO[state] ? state : 'none'
    }

    function readError(payload, status) {
      const data = isObj(payload) ? payload : {}
      const error = isObj(data.error) ? data.error : null
      const code = error ? text(error.code) : ''
      const message = error ? text(error.message) : ''
      if (message) return message
      if (code && ERROR_HINTS[code]) return ERROR_HINTS[code]
      if (status === 404) return '插件接口不存在（HTTP 404），插件可能未启用或版本过旧。'
      if (status === 401) return '面板令牌缺失或已失效：请刷新页面（插件每次加载都会生成新的页面令牌）。'
      if (status === 403) return '请求被拒绝：只接受当前 DSH 页面发起的面板请求。'
      if (typeof data.message === 'string' && data.message.trim()) return data.message
      return status ? `插件接口返回失败（HTTP ${status}）。` : '插件接口返回失败。'
    }

    async function requestJson(url, init) {
      let response
      try {
        response = await fetch(url, init || {})
      } catch (error) {
        throw new Error(`无法连接插件接口：${messageOf(error)}`)
      }
      let payload = null
      try {
        payload = await response.json()
      } catch (error) {
        throw new Error(`插件接口返回了无法解析的内容（HTTP ${response.status}）。`)
      }
      if (!isObj(payload)) {
        throw new Error(`插件接口返回为空（HTTP ${response.status}）。`)
      }
      if (payload.ok === false || !response.ok) {
        throw new Error(readError(payload, response.status))
      }
      return payload
    }

    /** Host 每次加载生成的页面令牌（注入在 index 的 <head> 里）；接口必须带它。 */
    const PAGE_TOKEN = (() => {
      try {
        if (typeof window === 'undefined') return ''
        return typeof window.__DSH_SECURITY_JUDGE_TOKEN__ === 'string' ? window.__DSH_SECURITY_JUDGE_TOKEN__ : ''
      } catch {
        return ''
      }
    })()

    function authHeaders(extra) {
      return { ...(extra || {}), ...(PAGE_TOKEN ? { 'x-security-judge-token': PAGE_TOKEN } : {}) }
    }

    function getJson(path) {
      return requestJson(API + path, { headers: authHeaders({ accept: 'application/json' }) })
    }

    function postAction(action, payload) {
      return requestJson(API + '/action', {
        method: 'POST',
        headers: authHeaders({ 'content-type': 'application/json', accept: 'application/json' }),
        body: JSON.stringify({ action, payload: payload === undefined ? null : payload }),
      })
    }

    // ============================================================
    // 数据形状兜底（Host 字段缺失 / 为 null 时面板不能白屏）
    // ============================================================
    function normalizeRule(raw) {
      const r = isObj(raw) ? raw : {}
      return {
        id: text(r.id),
        level: text(r.level, 'L3'),
        applies: text(r.applies),
        title: text(r.title, '未命名规则'),
        criteria: text(r.criteria),
        auto: r.auto === true,
        check: text(r.check),
      }
    }

    function normalizeRuleGroup(raw) {
      const g = isObj(raw) ? raw : {}
      return {
        id: text(g.id, '?'),
        name: text(g.name, '未命名分组'),
        rules: arr(g.rules).filter(isObj).map(normalizeRule),
      }
    }

    /** 目录里的架构：比会话里的多 purpose / when / rules / conflictsWith。 */
    function normalizeArchitecture(raw) {
      const a = isObj(raw) ? raw : {}
      return {
        id: text(a.id),
        name: text(a.name, '未命名架构'),
        layer: text(a.layer, 'other'),
        layerName: text(a.layerName, '其他'),
        purpose: text(a.purpose),
        // 契约 §3.2 用 mandatory；早期 Host 只给了 tier，core 档等价于强制基线。
        mandatory: a.mandatory === true || text(a.tier) === 'core',
        stacks: arr(a.stacks).map((v) => text(v)).filter(Boolean),
        when: text(a.when),
        why: text(a.why),
        rules: arr(a.rules).map((v) => text(v)).filter(Boolean),
        conflictsWith: arr(a.conflictsWith).map((v) => text(v)).filter(Boolean),
        doc: text(a.doc),
      }
    }

    function normalizeConflict(raw) {
      const c = isObj(raw) ? raw : {}
      return {
        id: text(c.id),
        title: text(c.title, '未命名冲突'),
        severity: text(c.severity, 'tension'),
        a: text(c.a),
        b: text(c.b),
        detail: text(c.detail),
        resolution: text(c.resolution),
        rules: arr(c.rules).map((v) => text(v)).filter(Boolean),
        acknowledged: c.acknowledged === true,
        ackNote: text(c.ackNote),
      }
    }

    function normalizeSession(raw) {
      const s = isObj(raw) ? raw : {}
      const code = isObj(s.code) ? s.code : {}
      const review = isObj(s.review) ? s.review : {}
      const progress = isObj(s.progress) ? s.progress : {}
      const activity = isObj(s.activity) ? s.activity : {}
      const architectures = arr(s.architectures).filter(isObj).map(normalizeArchitecture)
      const architectureCount = num(s.architectureCount) || architectures.length
      return {
        id: text(s.id),
        title: text(s.title, '未命名会话'),
        cwd: text(s.cwd),
        status: STATUS_LABEL[text(s.status)] ? text(s.status) : 'unknown',
        createdAt: num(s.createdAt),
        lastActivityAt: num(s.lastActivityAt),
        category: text(s.category, 'unknown'),
        categoryName: text(s.categoryName, '未分类'),
        categoryWhy: arr(s.categoryWhy).map((v) => text(v)).filter(Boolean),
        code: {
          doing: code.doing === true,
          score: clamp(num(code.score), 0, 100),
          projectKind: PROJECT_KIND_LABEL[text(code.projectKind)] ? text(code.projectKind) : 'unknown',
          stacks: arr(code.stacks).map((v) => text(v)).filter(Boolean),
          signals: arr(code.signals).filter(isObj).map((sig) => ({
            kind: text(sig.kind, '信号'),
            detail: text(sig.detail),
            at: num(sig.at),
          })),
          files: arr(code.files).map((v) => text(v)).filter(Boolean),
        },
        architectures,
        architectureCount,
        distributionTarget: s.distributionTarget === true,
        distribution: isObj(s.distribution)
          ? {
            ok: s.distribution.ok === true,
            checkedAt: num(s.distribution.checkedAt),
            packageName: text(s.distribution.packageName),
            packageVersion: text(s.distribution.packageVersion),
            findings: arr(s.distribution.findings).filter(isObj).map((item) => ({
              file: text(item.file),
              why: text(item.why),
            })),
          }
          : null,
        conflicts: arr(s.conflicts).filter(isObj).map(normalizeConflict),
        review: {
          state: REVIEW_INFO[text(review.state)] ? text(review.state) : 'none',
          verdict: text(review.verdict, 'none'),
          unqualified: review.unqualified === true,
          redoCount: num(review.redoCount),
          enforcePaused: review.enforcePaused === true,
          coaching: review.coaching === true,
          requestedAt: num(review.requestedAt),
          score: num(review.score),
          turn: num(review.turn),
          attempts: num(review.attempts),
          enforced: num(review.enforced),
          lastAt: num(review.lastAt),
          passedRules: arr(review.passedRules).map((v) => text(v)).filter(Boolean),
          failedRules: arr(review.failedRules).filter(isObj).map((r) => ({
            id: text(r.id),
            level: text(r.level, 'L3'),
            title: text(r.title, '未命名规则'),
            reason: text(r.reason),
            source: text(r.source),
          })),
          missingRules: arr(review.missingRules).filter(isObj).map((r) => ({
            id: text(r.id),
            level: text(r.level, 'L3'),
            title: text(r.title, '未命名规则'),
          })),
          autoViolations: arr(review.autoViolations).filter(isObj).map((v) => ({
            id: text(v.id),
            level: text(v.level, 'L3'),
            findings: arr(v.findings).filter(isObj).map((f) => ({
              file: text(f.file),
              line: num(f.line),
              snippet: text(f.snippet),
              why: text(f.why),
            })),
          })),
          attested: num(review.attested),
          waivedCount: arr(review.waived).length,
        },
        progress: {
          inScope: num(progress.inScope),
          l1: num(progress.l1),
          autoPass: num(progress.autoPass),
          attested: num(progress.attested),
          failed: num(progress.failed),
        },
        activity: {
          lastTool: text(activity.lastTool),
          lastFile: text(activity.lastFile),
          codeTurns: num(activity.codeTurns),
          turns: num(activity.turns),
        },
      }
    }

    function normalizeState(payload) {
      const data = isObj(payload) ? payload : {}
      const authority = isObj(data.authority) ? data.authority : {}
      const settings = isObj(data.settings) ? data.settings : {}
      const stats = isObj(data.stats) ? data.stats : {}
      const catalog = isObj(data.catalog) ? data.catalog : {}
      const plugin = isObj(data.plugin) ? data.plugin : {}
      const version = text(data.version, '1.0.0')
      const rawRuleVersion = text(catalog.ruleVersion) || text(plugin.ruleVersion)
      const mode = MODE_INFO[text(settings.mode)] ? text(settings.mode) : 'advisory'
      return {
        version,
        ruleVersion: rawRuleVersion
          ? (rawRuleVersion.startsWith('v') ? rawRuleVersion : `v${rawRuleVersion}`)
          : `v${version}`,
        generatedAt: num(data.generatedAt),
        authority: {
          granted: authority.granted === true,
          grantedAt: num(authority.grantedAt) || null,
          requestedAt: num(authority.requestedAt) || null,
          scope: text(authority.scope, DEFAULT_SCOPE),
          charter: text(authority.charter, DEFAULT_CHARTER),
          canGate: authority.canGate === true,
        },
        settings: {
          mode,
          autoScanMs: numberOrDefault(settings.autoScanMs, 15000),
          maxEnforcePerSession: numberOrDefault(settings.maxEnforcePerSession, 0),
          blockWithoutPass: settings.blockWithoutPass === true,
        },
        stats: {
          liveSessions: num(stats.liveSessions),
          codeSessions: num(stats.codeSessions),
          passed: num(stats.passed),
          pending: num(stats.pending),
          failed: num(stats.failed),
          unjudged: num(stats.unjudged),
          conflicted: num(stats.conflicted),
          authority: stats.authority === true,
        },
        sessions: arr(data.sessions).filter(isObj).map(normalizeSession),
        catalog: {
          ruleGroups: arr(catalog.ruleGroups).filter(isObj).map(normalizeRuleGroup),
          architectures: arr(catalog.architectures).filter(isObj).map(normalizeArchitecture),
          conflicts: arr(catalog.conflicts).filter(isObj).map(normalizeConflict),
        },
      }
    }

    /** 首次渲染 / state 为 null 时的空骨架，保证页面不白屏。 */
    const EMPTY_STATE = normalizeState(null)

    // ============================================================
    // 展示组件
    // ============================================================
    function Badge(props) {
      const color = TONE_COLOR[props.tone] || TONE_COLOR.muted
      const style = { ...S.badge, color, borderColor: color }
      if (props.background) style.background = props.background
      return h('span', { style, title: props.title || undefined }, props.children)
    }

    function LevelBadge(props) {
      const info = levelInfo(props.level)
      return h(Badge, { tone: info.tone, title: info.hint || undefined }, info.text)
    }

    function SeverityBadge(props) {
      const info = severityInfo(props.severity)
      return h('span', {
        title: SEVERITY_HINT[text(props.severity)] || undefined,
        style: {
          ...S.badge,
          color: info.color,
          borderColor: info.border,
          borderStyle: info.dashed ? 'dashed' : 'solid',
          background: info.background,
        },
      }, info.text)
    }

    function Card(props) {
      return h('section', { style: S.card },
        props.title
          ? h('div', { style: S.cardHead },
            h('h3', { style: S.cardTitle }, props.title),
            props.extra ? h('span', { style: S.cardExtra }, props.extra) : null,
          )
          : null,
        props.children,
      )
    }

    function EmptyHint(props) {
      return h('p', { style: S.empty }, props.children)
    }

    /** 单条架构冲突：严重度配色 + 展开处理建议 + 登记结论。 */
    function ConflictItem(props) {
      const conflict = props.conflict
      const info = severityInfo(conflict.severity)
      const resolutionOpen = props.resolutionOpen === true
      const ackOpen = props.ackOpen === true
      const ackBusy = props.ackBusy === true
      const disabled = props.anyBusy === true

      return h('div', { style: { ...S.conflictItem, borderLeft: `3px solid ${info.border}` } },
        h('div', { style: S.conflictHead },
          h(SeverityBadge, { severity: conflict.severity }),
          h('span', { style: S.conflictTitle }, conflict.title || conflict.id || '未命名冲突'),
          conflict.acknowledged ? h(Badge, { tone: 'success' }, '已登记') : null,
          conflict.a || conflict.b
            ? h('span', { style: S.conflictMeta }, `${conflict.a || '?'} ↔ ${conflict.b || '?'}`)
            : null,
        ),
        conflict.detail ? h('p', { style: S.conflictDetail }, conflict.detail) : null,
        arr(conflict.rules).length
          ? h('p', { style: S.tiny }, `涉及规则：${arr(conflict.rules).join('、')}`)
          : null,
        h('div', { style: S.actionRow },
          h('button', {
            type: 'button',
            style: S.linkButton,
            onClick: props.onToggleResolution,
          }, resolutionOpen ? '收起处理建议' : '查看处理建议'),
          h('button', {
            type: 'button',
            style: S.linkButton,
            disabled: disabled || ackOpen,
            onClick: props.onOpenAck,
          }, conflict.acknowledged ? '重新登记处理结论' : '登记处理结论'),
        ),
        resolutionOpen
          ? h('p', { style: S.conflictResolution }, conflict.resolution || '（Host 未给出处理建议）')
          : null,
        conflict.acknowledged && conflict.ackNote
          ? h('p', { style: S.tiny }, `已登记结论：${conflict.ackNote}`)
          : null,
        ackOpen
          ? h('div', { style: S.ackBar },
            h('p', { style: S.confirmText }, '登记这条架构冲突的处理结论（会记录到该会话的评审里）。'),
            h('textarea', {
              style: S.textarea,
              rows: 3,
              value: props.ackText,
              placeholder: '例如：以零信任为准，白名单仅用于可观测性；授权判断基于身份与设备。',
              onChange: (event) => props.onAckChange(event.target.value),
            }),
            h('div', { style: S.actionRow },
              h('button', {
                type: 'button',
                style: disabled || ackBusy || !text(props.ackText).trim()
                  ? { ...S.button, ...S.buttonDisabled }
                  : S.button,
                disabled: disabled || ackBusy || !text(props.ackText).trim(),
                onClick: props.onSaveAck,
              }, ackBusy ? '保存中…' : '保存结论'),
              h('button', {
                type: 'button',
                style: disabled ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
                disabled,
                onClick: props.onCancelAck,
              }, '取消'),
            ),
          )
          : null,
      )
    }

    /** 单个会话：折叠行 + 展开明细（信号 / 架构 / 冲突 / 评审进度 / 操作）。 */
    function SessionItem(props) {
      const session = props.session
      const code = session.code
      const review = session.review
      const reviewState = sessionReviewState(review)
      const reviewMeta = reviewInfo(reviewState)
      const open = props.expanded === true
      const busy = text(props.busy)
      const anyBusy = props.anyBusy === true
      const authorityGranted = props.authorityGranted === true
      const reviewBusy = busy === `review:${session.id}`
      const remindBusy = busy === `remind:${session.id}`
      const openConflicts = arr(session.conflicts).filter((item) => item.acknowledged !== true).length
      const archCount = session.architectureCount
      const archNames = arr(session.architectures).map((item) => item.name).filter(Boolean)
      const progress = session.progress
      const covered = num(progress.autoPass) + num(progress.attested)
      const inScope = num(progress.inScope)
      const percent = inScope > 0 ? clamp(Math.round((covered / inScope) * 100), 0, 100) : 0

      const signalRows = arr(code.signals).slice(0, 6).map((signal, index) => h('li', {
        key: `signal-${index}`,
        style: S.listItem,
      },
        h('span', { style: S.mono }, signal.kind),
        signal.detail ? ` · ${signal.detail}` : '',
        signal.at ? ` · ${formatTime(signal.at)}` : '',
      ))

      const fileRows = arr(code.files).slice(0, 6).map((file, index) => h('li', {
        key: `file-${index}`,
        style: S.listItem,
      }, h('span', { style: S.mono }, file)))

      const archCards = arr(session.architectures).map((arch, index) => h('div', {
        key: `arch-${arch.id || index}`,
        style: S.archCard,
      },
        h('div', { style: S.archHead },
          h('span', { style: S.archName }, arch.name),
          h('span', { style: S.archBadges },
            arch.layerName ? h(Badge, { tone: 'muted' }, arch.layerName) : null,
            arch.mandatory
              ? h(Badge, { tone: 'error', title: '这个程序必须采用的基线架构。' }, '强制基线')
              : h(Badge, { tone: 'muted' }, '按需选用'),
          ),
        ),
        h('p', { style: S.archText }, arch.why || arch.purpose || '（Host 未给出推荐理由）'),
        arch.doc ? h('p', { style: S.archMeta }, `依据：${arch.doc}`) : null,
      ))

      const conflictNodes = arr(session.conflicts).map((conflict) => h(ConflictItem, {
        key: `conflict-${conflict.id}`,
        conflict,
        resolutionOpen: props.openResolutions[`${session.id}|${conflict.id}`] === true,
        ackOpen: Boolean(props.ack && props.ack.conflictId === conflict.id),
        ackText: props.ackText,
        ackBusy: busy === `ack:${session.id}:${conflict.id}`,
        anyBusy,
        onToggleResolution: () => props.onToggleResolution(session.id, conflict.id),
        onOpenAck: () => props.onOpenAck(session.id, conflict.id),
        onAckChange: props.onAckChange,
        onSaveAck: () => props.onSaveAck(session.id, conflict.id),
        onCancelAck: props.onCancelAck,
      }))

      const violationFindings = (ruleId) => {
        const hit = arr(review.autoViolations).find((item) => item.id === ruleId)
        if (!hit) return []
        return arr(hit.findings).slice(0, 3)
      }

      const failedNodes = arr(review.failedRules).slice(0, LIST_LIMIT).map((rule, index) => h('li', {
        key: `failed-${rule.id || index}`,
        style: S.listItem,
      },
        h(LevelBadge, { level: rule.level }),
        ' ',
        h('span', { style: S.ruleId }, rule.id),
        ' ',
        h('span', { style: S.ruleTitle }, rule.title),
        rule.reason ? h('span', { style: S.ruleMeta }, ` — ${rule.reason}`) : null,
        rule.source ? h('span', { style: S.ruleMeta }, `（${rule.source === 'auto' ? '自动检查' : '会话提交'}）`) : null,
        violationFindings(rule.id).map((finding, findingIndex) => h('p', {
          key: `finding-${rule.id || index}-${findingIndex}`,
          style: S.tiny,
        },
          `${finding.file || '未知文件'}${finding.line > 0 ? `:${finding.line}` : ''}`,
          finding.why ? ` · ${finding.why}` : '',
          finding.snippet ? ` · ${finding.snippet}` : '',
        )),
      ))

      const missingNodes = arr(review.missingRules).slice(0, LIST_LIMIT).map((rule, index) => h('li', {
        key: `missing-${rule.id || index}`,
        style: S.listItem,
      },
        h(LevelBadge, { level: rule.level }),
        ' ',
        h('span', { style: S.ruleId }, rule.id),
        ' ',
        h('span', { style: S.ruleTitle }, rule.title),
        h('span', { style: S.ruleMeta }, ' — 未提交证据'),
      ))

      const body = h('div', { style: S.sessionBody },
        // 1. 代码识别信号
        h('div', { style: S.subCard },
          h('div', { style: S.subHead },
            h('h4', { style: S.subTitle }, '代码识别信号'),
            h('span', { style: S.subExtra },
              `${arr(code.signals).length} 条信号 · ${arr(code.files).length} 个文件`),
          ),
          h('div', { style: S.subBody },
            h('div', { style: S.kv },
              h('span', { style: S.kvKey }, '是否做代码'),
              h('span', { style: S.kvValue },
                code.doing ? `是 · ${projectKindText(code.projectKind)}` : '未见代码工作'),
              h('span', { style: S.kvKey }, '工作强度'),
              h('span', { style: S.kvValue }, code.doing ? `${code.score} / 100` : '—'),
              h('span', { style: S.kvKey }, '会话状态'),
              h('span', { style: S.kvValue },
                `${STATUS_LABEL[session.status]} · 最后活动 ${formatRelative(session.lastActivityAt)}`),
              h('span', { style: S.kvKey }, '工具痕迹'),
              h('span', { style: S.kvValue },
                `${session.activity.turns} 回合（代码回合 ${session.activity.codeTurns}）`
                + (session.activity.lastTool ? ` · 最近工具 ${session.activity.lastTool}` : '')),
            ),
            arr(code.stacks).length
              ? h('div', { style: S.chips },
                arr(code.stacks).map((stack, index) => h('span', {
                  key: `stack-${index}`,
                  style: S.chip,
                }, stack)))
              : null,
            signalRows.length
              ? h('ul', { style: S.list }, signalRows)
              : h(EmptyHint, null, '还没有代码识别信号。'),
            fileRows.length
              ? h('div', { style: S.subBody },
                h('p', { style: S.tiny }, '最近改动的文件：'),
                h('ul', { style: S.list }, fileRows))
              : null,
            arr(code.signals).length > 6
              ? h('p', { style: S.tiny }, `还有 ${arr(code.signals).length - 6} 条信号未显示。`)
              : null,
          ),
        ),

        // 2. 需要的架构
        h('div', { style: S.subCard },
          h('div', { style: S.subHead },
            h('h4', { style: S.subTitle }, '需要的代码安全防御架构'),
            h(Badge, { tone: archCount > 0 ? 'info' : 'muted' }, archCountText(archCount)),
          ),
          h('p', { style: S.hint },
            archCount > 0
              ? `本程序需要 ${archCount} 种代码安全防御架构${archNames.length ? `：${archNames.slice(0, 4).join('、')}${archNames.length > 4 ? ' 等' : ''}` : ''}。`
              : 'Host 还没有判定这个程序需要几种架构（可能还没扫描到足够的代码信号）。'),
          archCards.length
            ? h('div', { style: S.subBody }, archCards)
            : h(EmptyHint, null, '还没有推荐架构清单。'),
        ),

        // 3. 架构冲突
        h('div', { style: S.subCard },
          h('div', { style: S.subHead },
            h('h4', { style: S.subTitle }, '架构冲突'),
            h(Badge, { tone: openConflicts > 0 ? 'warn' : 'muted' },
              openConflicts > 0 ? `未登记 ${openConflicts} 条` : '无未登记冲突'),
          ),
          h('p', { style: S.tiny },
            '严重度：硬冲突（红）＞ 重叠（橙）＞ 张力（黄）。登记处理结论后会记录到该会话的评审里。'),
          conflictNodes.length
            ? h('div', { style: S.subBody }, conflictNodes)
            : h(EmptyHint, null, '没有检测到架构冲突。'),
        ),

        // 4. 评审进度
        h('div', { style: S.subCard },
          h('div', { style: S.subHead },
            h('h4', { style: S.subTitle }, '评审进度'),
            h(Badge, { tone: reviewMeta.tone }, reviewMeta.text),
          ),
          h('div', { style: S.progressGrid },
            h('div', { style: S.progressCell },
              h('span', { style: S.progressCellValue }, String(progress.inScope)),
              h('span', { style: S.progressCellLabel }, '在范围内')),
            h('div', { style: S.progressCell },
              h('span', { style: S.progressCellValue }, String(progress.l1)),
              h('span', { style: S.progressCellLabel }, 'L1 强制项')),
            h('div', { style: S.progressCell },
              h('span', { style: { ...S.progressCellValue, color: TONE_COLOR.success } }, String(progress.autoPass)),
              h('span', { style: S.progressCellLabel }, '自动通过')),
            h('div', { style: S.progressCell },
              h('span', { style: S.progressCellValue }, String(progress.attested)),
              h('span', { style: S.progressCellLabel }, '已提交证据')),
            h('div', { style: S.progressCell },
              h('span', {
                style: { ...S.progressCellValue, color: progress.failed > 0 ? TONE_COLOR.error : undefined },
              }, String(progress.failed)),
              h('span', { style: S.progressCellLabel }, '失败')),
          ),
          h('div', { style: S.progressTrack },
            h('div', { style: { ...S.progressFill, width: `${percent}%` } }),
          ),
          h('p', { style: S.tiny }, `评审覆盖 ${percent}%（${covered} / ${inScope} 条在范围规则）`),
          review.unqualified
            ? h('p', { style: { ...S.tiny, color: TONE_COLOR.error } },
              `不合格：必须重做${review.redoCount ? `（已强制重做 ${review.redoCount} 次）` : ''}${review.enforcePaused ? ' · 用户已暂停强制重做' : ' · 合格为止'}${review.coaching ? ' · 已进入教学模式' : ''}`)
            : null,
          review.requestedAt
            ? h('p', { style: S.tiny },
              `用户已要求评审本会话（${formatTime(review.requestedAt)}）${review.state === 'passed' ? ' · 已合格' : ' · 等待提交评审证据'}`)
            : null,
          session.distributionTarget
            ? h('div', { style: S.kv },
              h('span', { style: S.kvKey }, '分发自检（J 组）'),
              h('span', { style: { ...S.kvValue, color: session.distribution && !session.distribution.ok ? TONE_COLOR.error : undefined } },
                session.distribution
                  ? (session.distribution.ok
                    ? `通过${session.distribution.packageName ? ` · ${session.distribution.packageName}@${session.distribution.packageVersion || '?'}` : ''}`
                    : `未通过（${arr(session.distribution.findings).length} 个问题）`)
                  : '尚未检测'),
              arr(session.distribution && session.distribution.findings).slice(0, 4).map((item, index) => h('span', {
                key: `dist-${index}`,
                style: { ...S.kvValue, color: TONE_COLOR.error },
              }, `${item.file || '安装包'}：${item.why}`)),
            )
            : null,
          h('div', { style: S.kv },
            h('span', { style: S.kvKey }, '评审结论'),
            h('span', { style: S.kvValue },
              `${VERDICT_TEXT[review.verdict] || review.verdict || '未评审'} · 评分 ${review.score}`),
            h('span', { style: S.kvKey }, '回合 / 尝试 / 重做'),
            h('span', { style: S.kvValue },
              `第 ${review.turn} 回合 · 评审 ${review.attempts} 次 · 强制重做 ${review.redoCount} 次（累计 ${review.enforced} 次）`),
            h('span', { style: S.kvKey }, '最近评审'),
            h('span', { style: S.kvValue }, formatTime(review.lastAt)),
            h('span', { style: S.kvKey }, '已提交规则'),
            h('span', { style: S.kvValue },
              `${review.passedRules.length} 条通过 · ${review.attested} 条证据${review.waivedCount ? ` · ${review.waivedCount} 条豁免` : ''}`),
          ),
          h('div', { style: S.subHead },
            h('h4', { style: S.subTitle }, `失败项（${arr(review.failedRules).length}）`),
          ),
          failedNodes.length
            ? h('ul', { style: S.list }, failedNodes)
            : h(EmptyHint, null, '没有失败项。'),
          h('div', { style: S.subHead },
            h('h4', { style: S.subTitle }, `缺失项（${arr(review.missingRules).length}）`),
          ),
          missingNodes.length
            ? h('ul', { style: S.list }, missingNodes)
            : h(EmptyHint, null, '没有缺失项。'),
        ),

        // 5. 操作
        h('div', { style: S.actionRow },
          h('button', {
            type: 'button',
            style: anyBusy || !session.id ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
            disabled: anyBusy || !session.id,
            onClick: () => props.onReview(session.id),
          }, reviewBusy ? '评审中…' : '评审该会话'),
          h('button', {
            type: 'button',
            style: anyBusy || !code.doing || !session.id || !authorityGranted
              ? { ...S.buttonSecondary, ...S.buttonDisabled }
              : S.buttonSecondary,
            disabled: anyBusy || !code.doing || !session.id || !authorityGranted,
            title: !authorityGranted
              ? '提醒需要先在授权卡授予评审权限'
              : (code.doing ? '向该会话注入一条评审判官提醒' : '只有做代码的会话才能提醒'),
            onClick: () => props.onRemind(session.id),
          }, remindBusy ? '提醒中…' : '提醒该会话'),
          h('button', {
            type: 'button',
            style: anyBusy || !code.doing || !session.id || !authorityGranted
              ? { ...S.buttonSecondary, ...S.buttonDisabled }
              : S.buttonSecondary,
            disabled: anyBusy || !code.doing || !session.id || !authorityGranted,
            title: !authorityGranted
              ? '暂停/恢复强制重做需要先在授权卡授予评审权限'
              : '用户最高权限：暂停后不再自动催办，但评审结论仍是不合格',
            onClick: () => props.onToggleEnforce(session.id, !review.enforcePaused),
          }, review.enforcePaused ? '恢复强制重做' : '暂停强制重做'),
          !authorityGranted
            ? h('span', { style: S.tiny }, '提醒与强制重做属于评审权限，授权后才能使用。')
            : (!code.doing
              ? h('span', { style: S.tiny }, '该会话当前没有代码工作，提醒与重做按钮已禁用。')
              : null),
        ),
      )

      return h('div', { style: open ? { ...S.sessionRow, ...S.sessionRowOpen } : S.sessionRow },
        h('div', {
          style: S.sessionHead,
          role: 'button',
          tabIndex: 0,
          'aria-expanded': open ? 'true' : 'false',
          onClick: props.onToggle,
          onKeyDown: (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault()
              props.onToggle()
            }
          },
        },
          h('span', {
            style: { ...S.statusDot, background: statusColor(session.status) },
            title: STATUS_LABEL[session.status],
          }),
          h('div', { style: S.sessionMain },
            h('div', { style: S.sessionTitleRow },
              h('span', { style: S.sessionTitle }, session.title),
              h('span', { style: S.badgePlain }, STATUS_LABEL[session.status]),
              h('span', {
                style: S.chip,
                title: session.categoryWhy.length ? session.categoryWhy.join('；') : '依据标题、用户要求与代码证据分类',
              }, session.categoryName || '未分类'),
              code.doing
                ? h('span', { style: S.chip }, `做代码 · ${projectKindText(code.projectKind)}`)
                : h('span', { style: S.chipMuted }, '未见代码'),
            ),
            h('div', { style: S.sessionMeta },
              h('span', { style: S.mono }, session.cwd || '（工作目录未知）'),
              session.lastActivityAt
                ? h('span', null, ` · 最后活动 ${formatRelative(session.lastActivityAt)}`)
                : null,
            ),
          ),
          h('span', { style: S.sessionBadges },
            h(Badge, { tone: archCount > 0 ? 'info' : 'muted' }, archCountText(archCount)),
            h(Badge, { tone: reviewMeta.tone }, reviewMeta.text),
            openConflicts > 0 ? h(Badge, { tone: 'warn' }, `冲突 ${openConflicts}`) : null,
          ),
          h('span', { style: S.sessionCaret }, open ? '▾' : '▸'),
        ),
        open ? body : null,
      )
    }

    /** 规则目录：A~I 分组折叠。 */
    function RuleCatalog(props) {
      const groups = arr(props.groups)
      const openMap = isObj(props.openMap) ? props.openMap : {}
      const totalRules = groups.reduce((sum, group) => sum + arr(group.rules).length, 0)
      const anyOpen = groups.some((group) => openMap[group.id] === true)

      return h(Card, {
        title: '规则目录',
        extra: `${groups.length} 组 · ${totalRules} 条规则`,
      },
        h('p', { style: S.hint },
          'A~I 分组；等级 L1 强制 / L2 基线 / L3 建议。标「自动」的规则由 Host 扫描代码文本命中，其余需要会话 AI 提交证据。'),
        h('div', { style: S.actionRow },
          h('button', {
            type: 'button',
            style: S.linkButton,
            onClick: () => props.onToggleAll(!anyOpen),
          }, anyOpen ? '收起全部' : '展开全部'),
        ),
        groups.length
          ? h('div', { style: S.subBody },
            groups.map((group) => {
              const open = openMap[group.id] === true
              const autoCount = arr(group.rules).filter((rule) => rule.auto).length
              return h('div', { key: `group-${group.id}`, style: S.ruleGroup },
                h('button', {
                  type: 'button',
                  style: S.ruleHeadButton,
                  'aria-expanded': open ? 'true' : 'false',
                  onClick: () => props.onToggleGroup(group.id),
                },
                  h('span', { style: S.ruleHeadText },
                    h('span', { style: S.ruleGroupTitle },
                      `${open ? '▾' : '▸'} ${group.id} · ${group.name}`),
                    h('span', { style: S.ruleGroupMeta },
                      `${arr(group.rules).length} 条${autoCount ? ` · 自动 ${autoCount}` : ''}`),
                  ),
                  h('span', { style: S.tiny }, open ? '收起' : '展开'),
                ),
                open
                  ? h('div', { style: S.ruleBody },
                    arr(group.rules).map((rule, index) => h('div', {
                      key: `rule-${rule.id || index}`,
                      style: S.ruleRow,
                    },
                      h('div', { style: S.ruleRowHead },
                        h('span', { style: S.ruleId }, rule.id),
                        h(LevelBadge, { level: rule.level }),
                        h('span', { style: S.ruleTitle }, rule.title),
                        rule.auto ? h(Badge, { tone: 'info' }, '自动') : h(Badge, { tone: 'muted' }, '需证据'),
                      ),
                      rule.applies ? h('span', { style: S.ruleMeta }, `适用：${rule.applies}`) : null,
                      rule.criteria ? h('p', { style: S.ruleCriteria }, rule.criteria) : null,
                      rule.check ? h('p', { style: S.ruleCriteria }, `自动检查：${rule.check}`) : null,
                    )),
                  )
                  : null,
              )
            }),
          )
          : h(EmptyHint, null, 'Host 还没有返回规则目录。'),
      )
    }

    /** 架构目录：按层分组折叠。 */
    function ArchitectureCatalog(props) {
      const architectures = arr(props.architectures)
      const openMap = isObj(props.openMap) ? props.openMap : {}
      const layers = useMemo(() => {
        const map = new Map()
        for (const arch of architectures) {
          const key = arch.layer || 'other'
          if (!map.has(key)) map.set(key, { id: key, name: arch.layerName || key, items: [] })
          map.get(key).items.push(arch)
        }
        return Array.from(map.values())
      }, [architectures])

      return h(Card, {
        title: '架构目录',
        extra: `${layers.length} 层 · ${architectures.length} 种架构`,
      },
        h('p', { style: S.hint },
          '按层分组（判据层 / 理论层 / 骨架层 / 方法层 / 供应链 / AI / 后量子等）。「何时需要」说明这类程序在什么情况下必须采用该架构。'),
        layers.length
          ? h('div', { style: S.subBody },
            layers.map((layer) => {
              const open = openMap[layer.id] === true
              const mandatoryCount = layer.items.filter((item) => item.mandatory).length
              return h('div', { key: `layer-${layer.id}`, style: S.ruleGroup },
                h('button', {
                  type: 'button',
                  style: S.ruleHeadButton,
                  'aria-expanded': open ? 'true' : 'false',
                  onClick: () => props.onToggleLayer(layer.id),
                },
                  h('span', { style: S.ruleHeadText },
                    h('span', { style: S.ruleGroupTitle },
                      `${open ? '▾' : '▸'} ${layer.name}`),
                    h('span', { style: S.ruleGroupMeta },
                      `${layer.items.length} 种${mandatoryCount ? ` · 强制 ${mandatoryCount}` : ''}`),
                  ),
                  h('span', { style: S.tiny }, open ? '收起' : '展开'),
                ),
                open
                  ? h('div', { style: S.subBody },
                    layer.items.map((arch, index) => h('div', {
                      key: `arch-${arch.id || index}`,
                      style: S.archCard,
                    },
                      h('div', { style: S.archHead },
                        h('span', { style: S.archName }, arch.name),
                        h('span', { style: S.archBadges },
                          arch.mandatory
                            ? h(Badge, { tone: 'error' }, '强制基线')
                            : h(Badge, { tone: 'muted' }, '按需选用'),
                          arch.id ? h('span', { style: S.mono }, arch.id) : null,
                        ),
                      ),
                      arch.purpose ? h('p', { style: S.archText }, `作用：${arch.purpose}`) : null,
                      arch.when ? h('p', { style: S.archText }, `何时需要：${arch.when}`) : null,
                      arr(arch.stacks).length
                        ? h('p', { style: S.archMeta }, `适用技术栈：${arr(arch.stacks).join('、')}`)
                        : null,
                      arr(arch.rules).length
                        ? h('p', { style: S.archMeta }, `关联规则：${arr(arch.rules).join('、')}`)
                        : null,
                      arr(arch.conflictsWith).length
                        ? h('p', { style: S.archMeta }, `与这些架构存在冲突：${arr(arch.conflictsWith).join('、')}`)
                        : null,
                      arch.doc ? h('p', { style: S.tiny }, `依据：${arch.doc}`) : null,
                    )),
                  )
                  : null,
              )
            }),
          )
          : h(EmptyHint, null, 'Host 还没有返回架构目录。'),
      )
    }

    /** 冲突矩阵：全部冲突对 + 严重度 + 处理建议。 */
    function ConflictMatrix(props) {
      const conflicts = arr(props.conflicts)
      const counts = { hard: 0, overlap: 0, tension: 0 }
      for (const conflict of conflicts) {
        const key = text(conflict.severity)
        if (counts[key] !== undefined) counts[key] += 1
      }
      return h(Card, {
        title: '架构冲突矩阵',
        extra: `${conflicts.length} 对 · 硬 ${counts.hard} / 重叠 ${counts.overlap} / 张力 ${counts.tension}`,
      },
        h('p', { style: S.hint },
          '架构之间两两比较的结果。硬冲突必须处理后才能算通过；重叠与张力需要在实现上明确主责或记录取舍理由。'),
        conflicts.length
          ? h('div', { style: S.subBody },
            conflicts.map((conflict, index) => h('div', {
              key: `matrix-${conflict.id || index}`,
              style: { ...S.conflictItem, borderLeft: `3px solid ${severityInfo(conflict.severity).border}` },
            },
              h('div', { style: S.conflictHead },
                h(SeverityBadge, { severity: conflict.severity }),
                h('span', { style: S.conflictTitle }, conflict.title || conflict.id || '未命名冲突'),
                conflict.a || conflict.b
                  ? h('span', { style: S.conflictMeta }, `${conflict.a || '?'} ↔ ${conflict.b || '?'}`)
                  : null,
              ),
              conflict.detail ? h('p', { style: S.conflictDetail }, conflict.detail) : null,
              h('p', { style: S.conflictResolution }, conflict.resolution || '（Host 未给出处理建议）'),
              arr(conflict.rules).length
                ? h('p', { style: S.tiny }, `涉及规则：${arr(conflict.rules).join('、')}`)
                : null,
            )),
          )
          : h(EmptyHint, null, 'Host 还没有返回冲突矩阵。'),
      )
    }

    /** 面板渲染异常兜底：避免一个坏字段让整个 slot 空白。 */
    class PanelErrorBoundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { error: null }
      }

      static getDerivedStateFromError(error) {
        return { error }
      }

      componentDidCatch(error) {
        if (typeof console !== 'undefined' && typeof console.warn === 'function') {
          console.warn('[security-judge] 面板渲染出错：', error)
        }
      }

      render() {
        if (this.state.error) {
          return h('div', { style: S.panel },
            h('div', { style: S.scroller },
              h('div', { style: S.stack },
                h('div', { style: { ...S.banner, ...S.bannerError } },
                  h('p', { style: S.error },
                    `面板渲染出错：${messageOf(this.state.error)}。请刷新页面后重试。`),
                ),
              ),
            ),
          )
        }
        return this.props.children
      }
    }

    // ============================================================
    // 主面板
    // ============================================================
    function SecurityJudgePanel() {
      const [state, setState] = useState(null)
      const [loading, setLoading] = useState(true)
      const [error, setError] = useState('')
      const [notice, setNotice] = useState(null)
      const [busy, setBusy] = useState('')
      const [lastRefreshed, setLastRefreshed] = useState(0)
      const [expanded, setExpanded] = useState({})
      const [openResolutions, setOpenResolutions] = useState({})
      const [openRuleGroups, setOpenRuleGroups] = useState({})
      const [openLayers, setOpenLayers] = useState({})
      const [authorityStep, setAuthorityStep] = useState('')
      const [ackTarget, setAckTarget] = useState(null)
      const [ackText, setAckText] = useState('')
      const [settingsDraft, setSettingsDraft] = useState(null)

      /** 防止同一时间发起两个写操作：轮询不读它，只有 action 用。 */
      const busyRef = useRef('')

      const applyState = useCallback((payload) => {
        const next = normalizeState(payload)
        setState(next)
        setLastRefreshed(Date.now())
        setLoading(false)
        return next
      }, [])

      const load = useCallback(async (options) => {
        const opts = isObj(options) ? options : {}
        if (opts.spinner === true) setLoading(true)
        try {
          const payload = await getJson('/state')
          applyState(payload)
          if (opts.clearError !== false) setError('')
          return true
        } catch (err) {
          setError(messageOf(err))
          setLoading(false)
          return false
        }
      }, [applyState])

      /** 统一执行 action：成功时优先用响应里的 state，否则重新拉一次 GET。 */
      const runAction = useCallback(async (name, payload, describe) => {
        if (busyRef.current) return null
        busyRef.current = name
        setBusy(name)
        setError('')
        setNotice(null)
        try {
          const result = await postAction(name, payload)
          let next = null
          if (isObj(result.state)) next = applyState(result.state)
          else {
            await load({ clearError: false })
            next = null
          }
          const label = typeof describe === 'function' ? describe(result, next) : (describe || '操作完成。')
          setNotice({ kind: 'ok', text: label })
          return result
        } catch (err) {
          setError(messageOf(err))
          return null
        } finally {
          busyRef.current = ''
          setBusy('')
        }
      }, [applyState, load])

      // 首次加载。
      useEffect(() => {
        load({ spinner: true }).catch(() => {})
      }, [load])

      // 轮询：2.5 秒一次；页面不可见时不发请求，重新可见时立刻补一次。
      useEffect(() => {
        let stopped = false
        const tick = () => {
          if (stopped) return
          if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
          load({ clearError: false }).catch(() => {})
        }
        const timer = window.setInterval(tick, POLL_MS)
        const onVisibility = () => {
          if (typeof document !== 'undefined' && document.visibilityState === 'visible') tick()
        }
        if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
          document.addEventListener('visibilitychange', onVisibility)
        }
        return () => {
          stopped = true
          window.clearInterval(timer)
          if (typeof document !== 'undefined' && typeof document.removeEventListener === 'function') {
            document.removeEventListener('visibilitychange', onVisibility)
          }
        }
      }, [load])

      const data = state || EMPTY_STATE
      const authority = data.authority
      const settings = data.settings
      const stats = data.stats
      const sessions = data.sessions
      const catalog = data.catalog
      const busyRefValue = busy !== ''
      const anyBusy = busyRefValue

      // ---------- 设置草稿 ----------
      const settingsValues = settingsDraft || {
        mode: settings.mode,
        autoScanSeconds: String(Math.max(3, Math.round(num(settings.autoScanMs) / 1000))),
        maxEnforcePerSession: String(Math.max(0, Math.round(num(settings.maxEnforcePerSession)))),
      }
      const draftMode = MODE_INFO[text(settingsValues.mode)] ? text(settingsValues.mode) : 'advisory'
      const currentSeconds = String(Math.max(3, Math.round(num(settings.autoScanMs) / 1000)))
      const currentMax = String(Math.max(0, Math.round(num(settings.maxEnforcePerSession))))
      const draftDirty = settingsDraft !== null && (
        settingsDraft.mode !== settings.mode
        || clampInt(settingsDraft.autoScanSeconds, 3, 120, 15) !== clampInt(currentSeconds, 3, 120, 15)
        || clampInt(settingsDraft.maxEnforcePerSession, 0, 200, 0) !== clampInt(currentMax, 0, 200, 0)
      )

      const updateDraft = (patch) => {
        setSettingsDraft((current) => {
          const base = current || {
            mode: settings.mode,
            autoScanSeconds: currentSeconds,
            maxEnforcePerSession: currentMax,
          }
          return { ...base, ...patch }
        })
      }

      // ---------- 交互 ----------
      const manualRefresh = async () => {
        if (busyRef.current) return
        busyRef.current = 'refresh'
        setBusy('refresh')
        try {
          const ok = await load({ spinner: true })
          if (ok) setNotice({ kind: 'ok', text: '已刷新评审状态。' })
        } finally {
          busyRef.current = ''
          setBusy('')
        }
      }

      const grantAuthority = async () => {
        const result = await runAction('grant-authority', { confirm: true }, '已获得代码安全防御评审授权。')
        if (result) setAuthorityStep('')
      }

      const revokeAuthority = async () => {
        const result = await runAction('revoke-authority', { confirm: true }, '已撤销评审授权，回到只读评审。')
        if (result) setAuthorityStep('')
      }

      const scanAll = async () => {
        await runAction('scan', {}, (result, next) => {
          if (next) {
            return `已重新扫描：活跃会话 ${next.stats.liveSessions} 个，代码会话 ${next.stats.codeSessions} 个，不合格 ${next.stats.failed} 个。`
          }
          return '已重新扫描所有活跃会话。'
        })
      }

      const reviewSession = async (sessionId) => {
        if (!sessionId) return
        await runAction('review', { sessionId }, (result, next) => {
          if (next) {
            const hit = next.sessions.find((item) => item.id === sessionId)
            if (hit) return `已受理评审：「${hit.title}」当前 ${reviewInfo(sessionReviewState(hit.review)).text}。`
          }
          return '已受理评审该会话。'
        })
      }

      const remindSession = async (sessionId) => {
        if (!sessionId) return
        await runAction('remind', { sessionId }, '已向该会话注入评审提醒（要求重做）。')
      }

      const toggleEnforce = async (sessionId, paused) => {
        if (!sessionId) return
        await runAction('pause-enforce', { sessionId, paused }, paused
          ? '已暂停强制重做：评审结论仍是不合格，只是暂时不再自动催办。'
          : '已恢复强制重做：不合格会继续要求重做，直到合格为止。')
      }

      const saveAck = async (sessionId, conflictId) => {
        const resolution = text(ackText).trim()
        if (!sessionId || !conflictId || !resolution) return
        const result = await runAction('ack-conflict', { sessionId, conflictId, resolution }, '已登记架构冲突的处理结论。')
        if (result) {
          setAckTarget(null)
          setAckText('')
        }
      }

      const saveSettings = async () => {
        const patch = {
          mode: draftMode,
          autoScanMs: clampInt(settingsValues.autoScanSeconds, 3, 120, 15) * 1000,
          maxEnforcePerSession: clampInt(settingsValues.maxEnforcePerSession, 0, 200, 0),
        }
        const result = await runAction('settings-save', { patch }, '设置已保存，会在下一次自动扫描时生效。')
        if (result) setSettingsDraft(null)
      }

      const toggleExpanded = (sessionId) => {
        if (!sessionId) return
        setExpanded((current) => ({ ...current, [sessionId]: current[sessionId] !== true }))
      }

      const toggleResolution = (sessionId, conflictId) => {
        const key = `${sessionId}|${conflictId}`
        setOpenResolutions((current) => ({ ...current, [key]: current[key] !== true }))
      }

      const openAck = (sessionId, conflictId) => {
        setAckTarget({ sessionId, conflictId })
        const session = sessions.find((item) => item.id === sessionId)
        const conflict = session ? arr(session.conflicts).find((item) => item.id === conflictId) : null
        setAckText(conflict ? conflict.ackNote : '')
      }

      const closeAck = () => {
        setAckTarget(null)
        setAckText('')
      }

      const toggleRuleGroup = (groupId) => {
        setOpenRuleGroups((current) => ({ ...current, [groupId]: current[groupId] !== true }))
      }

      const toggleAllRuleGroups = (open) => {
        const next = {}
        for (const group of catalog.ruleGroups) next[group.id] = open === true
        setOpenRuleGroups(next)
      }

      const toggleLayer = (layerId) => {
        setOpenLayers((current) => ({ ...current, [layerId]: current[layerId] !== true }))
      }

      // ---------- 授权卡 ----------
      const renderAuthority = () => {
        if (!authority.granted) {
          return h('section', {
            style: {
              ...S.card,
              border: '1.5px solid var(--dsw-alias-state-warn-primary)',
              background: 'var(--dsw-alias-bg-layer-2)',
            },
          },
            h('div', { style: S.cardHead },
              h('h3', { style: S.cardTitle }, '授权：评审与完成门禁'),
              h(Badge, { tone: 'warn' }, '未授权 · 只读审查'),
            ),
            h('p', { style: S.hint },
              '还没有获得授权。未授权时本插件只做只读评审：不会拦截代码任务算完成，也不会向会话注入提醒。'),
            h('p', { style: S.charter }, `权限边界：${authority.charter}`),
            h('div', { style: S.kv },
              h('span', { style: S.kvKey }, '授权范围'),
              h('span', { style: S.kvValue }, authority.scope),
              h('span', { style: S.kvKey }, '上次请求'),
              h('span', { style: S.kvValue }, authority.requestedAt ? formatTime(authority.requestedAt) : '还没有发起过'),
            ),
            h('div', { style: S.settingsGrid },
              h('div', { style: S.subCard },
                h('h4', { style: S.subTitle }, '获得授权后可以'),
                h('ul', { style: S.list },
                  h('li', { style: S.listItem }, '读取 / 汇总会话里已经产生的代码与工具痕迹；'),
                  h('li', { style: S.listItem }, '向代码会话注入评审提醒；'),
                  h('li', { style: S.listItem }, '按你选择的模式拦截「评审不合格的代码任务算完成」，不合格就会要求重做，直到合格。'),
                ),
              ),
              h('div', { style: S.subCard },
                h('h4', { style: S.subTitle }, '无论是否授权都不能'),
                h('ul', { style: S.list },
                  h('li', { style: S.listItem }, '修改代码；'),
                  h('li', { style: S.listItem }, '修改配置；'),
                  h('li', { style: S.listItem }, '代替你做决定；'),
                  h('li', { style: S.listItem }, '读取与代码安全防御无关的内容。'),
                ),
              ),
            ),
            authorityStep === 'grant'
              ? h('div', { style: S.confirmBar },
                h('p', { style: S.confirmText },
                  '确认把「代码安全防御评审」的权限授予本插件？授权后它可以在你选择的模式下拦截评审不合格的代码任务算完成，并要求重做到合格为止；它仍然不能修改代码、不能修改配置、不能代替你做决定。授权只用于代码安全防御规则与架构的评审。'),
                h('div', { style: S.actionRow },
                  h('button', {
                    type: 'button',
                    style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
                    disabled: anyBusy,
                    onClick: grantAuthority,
                  }, busy === 'grant-authority' ? '授权中…' : '确认授权'),
                  h('button', {
                    type: 'button',
                    style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
                    disabled: anyBusy,
                    onClick: () => setAuthorityStep(''),
                  }, '取消'),
                ),
              )
              : h('div', { style: S.actionRow },
                h('button', {
                  type: 'button',
                  style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
                  disabled: anyBusy,
                  onClick: () => setAuthorityStep('grant'),
                }, '请求用户授权'),
                h('span', { style: S.tiny }, '点击后会先在这里确认一次；Host 会把授权限定在代码安全防御评审范围内。'),
              ),
          )
        }

        return h('section', { style: S.card },
          h('div', { style: S.cardHead },
            h('h3', { style: S.cardTitle }, '授权：评审与完成门禁'),
            h(Badge, { tone: 'success' }, '已授权'),
          ),
          h('p', { style: S.charter }, `权限边界：${authority.charter}`),
          h('div', { style: S.kv },
            h('span', { style: S.kvKey }, '授权时间'),
            h('span', { style: S.kvValue }, authority.grantedAt ? formatTime(authority.grantedAt) : 'Host 未提供'),
            h('span', { style: S.kvKey }, '授权范围'),
            h('span', { style: S.kvValue }, authority.scope),
            h('span', { style: S.kvKey }, '完成门禁'),
            h('span', { style: S.kvValue },
              authority.canGate
                ? '具备：评审不合格的代码任务不能算完成，会要求重做到合格。'
                : '未启用：Host 暂未开放回合拦截。'),
            h('span', { style: S.kvKey }, '生效模式'),
            h('span', { style: S.kvValue },
              `${modeInfo(settings.mode).text}（${settings.mode}）—— ${modeInfo(settings.mode).hint}`),
          ),
          authorityStep === 'revoke'
            ? h('div', { style: S.confirmBarDanger },
              h('p', { style: S.confirmDangerText },
                '确认撤销授权？撤销后本插件回到只读评审，不再拦截不合格的代码任务，也不再注入提醒或强制重做。已生成的评审结论会保留。'),
              h('div', { style: S.actionRow },
                h('button', {
                  type: 'button',
                  style: anyBusy ? { ...S.buttonDanger, ...S.buttonDisabled } : S.buttonDanger,
                  disabled: anyBusy,
                  onClick: revokeAuthority,
                }, busy === 'revoke-authority' ? '撤销中…' : '确认撤销'),
                h('button', {
                  type: 'button',
                  style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
                  disabled: anyBusy,
                  onClick: () => setAuthorityStep(''),
                }, '取消'),
              ),
            )
            : h('div', { style: S.actionRow },
              h('button', {
                type: 'button',
                style: anyBusy ? { ...S.buttonDanger, ...S.buttonDisabled } : S.buttonDanger,
                disabled: anyBusy,
                onClick: () => setAuthorityStep('revoke'),
              }, '撤销授权'),
            ),
        )
      }

      // ---------- 统计条 ----------
      const statItems = [
        { key: 'liveSessions', label: '活跃会话', tone: 'muted' },
        { key: 'codeSessions', label: '正在做代码', tone: 'info' },
        { key: 'passed', label: '合格', tone: 'success' },
        { key: 'failed', label: '不合格', tone: 'error' },
        { key: 'pending', label: '待评审（未合格）', tone: 'warn' },
        { key: 'conflicted', label: '架构冲突', tone: 'error' },
      ]
      const renderStats = () => h('section', { style: S.card },
        h('div', { style: S.statGrid },
          statItems.map((item) => {
            const value = num(stats[item.key])
            const color = value > 0 ? TONE_COLOR[item.tone] : TONE_COLOR.muted
            return h('div', { key: item.key, style: S.statTile },
              h('span', { style: { ...S.statValue, color } }, String(value)),
              h('span', { style: S.statLabel }, item.label),
            )
          }),
        ),
        h('p', { style: S.tiny },
          `${sessions.length} 个会话在列表里 · ${stats.unjudged} 个未评审`
          + (stats.authority ? ' · 已具备授权' : ' · 未授权'),
        ),
      )

      // ---------- 会话列表 ----------
      const renderSessions = () => h('section', { style: S.card },
        h('div', { style: S.cardHead },
          h('h3', { style: S.cardTitle }, '会话评审'),
          h('div', { style: S.actionRow },
            h('span', { style: S.cardExtra }, `${sessions.length} 个`),
            h('button', {
              type: 'button',
              style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
              disabled: anyBusy,
              onClick: scanAll,
            }, busy === 'scan' ? '重扫中…' : '重扫全部会话'),
          ),
        ),
        h('p', { style: S.hint },
          '点会话行展开：代码识别信号、推荐架构与「需要几种」结论、架构冲突、评审进度与失败项。'),
        sessions.length
          ? h('div', { style: S.subBody },
            sessions.map((session) => h(SessionItem, {
              key: session.id || session.title,
              session,
              expanded: expanded[session.id] === true,
              openResolutions,
              ack: ackTarget && ackTarget.sessionId === session.id ? ackTarget : null,
              ackText,
              busy,
              anyBusy,
              authorityGranted: authority.granted,
              onToggle: () => toggleExpanded(session.id),
              onToggleResolution: toggleResolution,
              onOpenAck: openAck,
              onAckChange: setAckText,
              onSaveAck: saveAck,
              onCancelAck: closeAck,
              onReview: reviewSession,
              onRemind: remindSession,
              onToggleEnforce: toggleEnforce,
            })))
          : h(EmptyHint, null, '还没有识别到会话。等有会话开始做代码后，它会自动出现在这里。'),
      )

      // ---------- 设置卡 ----------
      const renderSettings = () => h('section', { style: S.card },
        h('div', { style: S.cardHead },
          h('h3', { style: S.cardTitle }, '设置'),
          h('span', { style: S.cardExtra },
            draftDirty ? '有未保存的修改' : '与 Host 当前设置一致'),
        ),
        h('div', { style: S.settingsGrid },
          h('div', { style: S.field },
            h('span', { style: S.fieldLabel }, '评审模式'),
            h('div', { style: S.segRow },
              Object.keys(MODE_INFO).map((mode) => h('button', {
                key: mode,
                type: 'button',
                style: draftMode === mode ? { ...S.segButton, ...S.segActive } : S.segButton,
                disabled: anyBusy,
                onClick: () => updateDraft({ mode }),
              }, MODE_INFO[mode].text)),
            ),
            h('p', { style: S.fieldHint }, modeInfo(draftMode).hint),
          ),
          h('div', { style: S.field },
            h('span', { style: S.fieldLabel }, '自动扫描间隔（秒）'),
            h('input', {
              type: 'number',
              min: 3,
              max: 120,
              step: 1,
              style: S.input,
              value: settingsValues.autoScanSeconds,
              disabled: anyBusy,
              onChange: (event) => updateDraft({ autoScanSeconds: event.target.value }),
            }),
            h('p', { style: S.fieldHint },
              `Host 自动扫描间隔，范围 3~120 秒；当前 ${formatMs(settings.autoScanMs)}。`),
          ),
          h('div', { style: S.field },
            h('span', { style: S.fieldLabel }, '单会话强制重做上限（0 = 合格为止）'),
            h('input', {
              type: 'number',
              min: 0,
              max: 200,
              step: 1,
              style: S.inputNarrow,
              value: settingsValues.maxEnforcePerSession,
              disabled: anyBusy,
              onChange: (event) => updateDraft({ maxEnforcePerSession: event.target.value }),
            }),
            h('p', { style: S.fieldHint },
              '0 = 合格为止，不设上限（默认）。大于 0 时到点停止自动催办，但结论仍是不合格，等用户处理。范围 0~200。'),
          ),
        ),
        h('hr', { style: S.divider }),
        h('div', { style: S.kv },
          h('span', { style: S.kvKey }, '评审不合格时拦截回合结束'),
          h('span', { style: S.kvValue },
            `${settings.blockWithoutPass ? '已开启' : '未开启'}（需授权；面板只读展示，改动由 Host 配置决定）`),
          h('span', { style: S.kvKey }, '是否具备门禁'),
          h('span', { style: S.kvValue },
            authority.canGate ? '具备（已授权）' : '不具备（未授权或 Host 未开启）'),
        ),
        h('div', { style: S.actionRow },
          h('button', {
            type: 'button',
            style: anyBusy || !draftDirty ? { ...S.button, ...S.buttonDisabled } : S.button,
            disabled: anyBusy || !draftDirty,
            onClick: saveSettings,
          }, busy === 'settings-save' ? '保存中…' : '保存设置'),
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
            disabled: anyBusy,
            onClick: () => setSettingsDraft(null),
          }, '还原为当前值'),
          h('span', { style: S.tiny }, '保存后由 Host 持久化，并在下一次自动扫描时生效。'),
        ),
      )

      // ---------- 顶栏 / 错误 / 提示 ----------
      const errorBanner = error
        ? h('div', { style: { ...S.banner, ...S.bannerError } },
          h('span', { style: S.error }, error),
          h('button', {
            type: 'button',
            style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
            disabled: anyBusy,
            onClick: manualRefresh,
          }, '重试'),
        )
        : null

      const noticeBanner = notice
        ? h('div', { style: { ...S.banner, ...S.bannerOk } },
          h('span', { style: S.ok }, notice.text),
          h('button', {
            type: 'button',
            style: S.linkButton,
            onClick: () => setNotice(null),
          }, '知道了'),
        )
        : null

      const headerActions = h('div', { style: S.actionRow },
        h('span', { style: S.tiny },
          `最后刷新：${lastRefreshed ? formatTime(lastRefreshed) : '从未'}`),
        h('button', {
          type: 'button',
          style: anyBusy ? { ...S.buttonSecondary, ...S.buttonDisabled } : S.buttonSecondary,
          disabled: anyBusy,
          onClick: manualRefresh,
        }, busy === 'refresh' ? '刷新中…' : '刷新'),
      )

      return h('div', { style: S.panel },
        h('div', { style: S.scroller },
          h('div', { style: S.stack },
            h('div', { style: S.header },
              h('div', { style: S.headerText },
                h('h2', { style: S.title }, '代码安全防御规则评审判官'),
                h('p', { style: S.subtitle }, `规则版本 ${data.ruleVersion} · 强制规则`),
                h('p', { style: S.tiny },
                  '自动识别做代码的会话；也可以在任意会话里对 AI 说「检查审核评审该会话」，评审判官会受理并开始评审。'),
              ),
              headerActions,
            ),
            errorBanner,
            noticeBanner,
            !state
              ? (loading
                ? h('section', { style: S.card },
                  h('p', { style: S.hint }, '正在读取评审状态…'))
                : h('section', { style: S.card },
                  h('h3', { style: S.cardTitle }, '暂时读不到评审状态'),
                  h('p', { style: S.hint },
                    '插件 Host 半边可能还没有就绪，或者接口还不可用。点下面的「重试」再读一次；如果一直失败，请确认插件已在当前配置里启用。'),
                  h('div', { style: S.actionRow },
                    h('button', {
                      type: 'button',
                      style: anyBusy ? { ...S.button, ...S.buttonDisabled } : S.button,
                      disabled: anyBusy,
                      onClick: manualRefresh,
                    }, '重试'),
                  ),
                ))
              : renderAuthority(),
            state ? renderStats() : null,
            state ? renderSessions() : null,
            state
              ? h(RuleCatalog, {
                groups: catalog.ruleGroups,
                openMap: openRuleGroups,
                onToggleGroup: toggleRuleGroup,
                onToggleAll: toggleAllRuleGroups,
              })
              : null,
            state
              ? h(ArchitectureCatalog, {
                architectures: catalog.architectures,
                openMap: openLayers,
                onToggleLayer: toggleLayer,
              })
              : null,
            state ? h(ConflictMatrix, { conflicts: catalog.conflicts }) : null,
            state ? renderSettings() : null,
            h('footer', { style: S.footer },
              h('p', { style: S.footerText }, authority.charter),
              h('p', { style: S.footerText },
                '本插件只做评审与提醒：不修改代码、不修改配置、不代替你做决定，也不读取与代码安全防御无关的内容。'),
            ),
          ),
        ),
      )
    }

    /** main 面板入口：外面包一层错误边界，避免坏数据让整个 slot 空白。 */
    function JudgePanelHost() {
      return h(PanelErrorBoundary, null, h(SecurityJudgePanel))
    }

    // ============================================================
    // 插件注册
    // ============================================================
    return {
      inject: ['slots', 'layout'],

      apply(ctx) {
        /** 点侧栏图标时切到本面板（宿主行点击也会切，重复调用无副作用）。 */
        const openPanel = () => {
          try {
            if (ctx.layout && typeof ctx.layout.selectPanel === 'function') ctx.layout.selectPanel(PANEL_ID)
          } catch (error) {
            // 面板还没注册时 selectPanel 会抛错；宿主自己的行点击逻辑会兜住，这里不需要报错。
          }
        }

        /** 侧栏 16~24px 盾牌 + 放大镜图标；props 由宿主提供 `{ size, active }`。 */
        function SidebarIcon(props) {
          const rawSize = Number(props && props.size)
          const size = clamp(Number.isFinite(rawSize) ? rawSize : 16, 16, 24)
          const active = Boolean(props && props.active)
          return h('svg', {
            viewBox: '0 0 24 24',
            width: size,
            height: size,
            xmlns: 'http://www.w3.org/2000/svg',
            'aria-hidden': 'true',
            focusable: 'false',
            style: { display: 'block', flex: 'none', cursor: 'pointer' },
            onClick: openPanel,
          },
            h('path', {
              d: 'M12 2.6 19.6 5.5v6.3c0 4.3-3.1 7.7-7.6 9.2-4.5-1.5-7.6-4.9-7.6-9.2V5.5z',
              fill: active ? 'var(--dsw-alias-brand-primary)' : 'var(--dsw-alias-label-secondary)',
              fillOpacity: active ? 0.2 : 0.08,
              stroke: 'currentColor',
              strokeWidth: 1.5,
              strokeLinejoin: 'round',
            }),
            h('circle', {
              cx: 10.9,
              cy: 10.4,
              r: 3,
              fill: 'none',
              stroke: 'currentColor',
              strokeWidth: 1.7,
            }),
            h('path', {
              d: 'M13.2 12.7l3.4 3.4',
              fill: 'none',
              stroke: 'currentColor',
              strokeWidth: 1.9,
              strokeLinecap: 'round',
            }),
          )
        }

        // 侧栏入口：id 与 main 的 key 必须一致，order 21 排在插件与会话入口之后。
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
          name: 'sidebar.panellist',
          id: PANEL_ID,
          order: 21,
          label: () => '代码安全评审判官',
        }, SidebarIcon))

        // 整页主面板：keyed slot，key = security-judge。
        ctx.slots.inject('main', () => ctx.slots.register({
          name: 'main',
          key: PANEL_ID,
        }, JudgePanelHost))
      },
    }
  },
})
