package com.example.prism.accessibility

import android.os.Build
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import java.util.Locale

/**
 * Walks the accessibility tree of the current window and pulls out every URL the user can see.
 *
 * This is the Android half of URL discovery; the text rules live in [UrlTextParser] so they can be
 * unit tested without a device. Traversal is breadth-first and hard-capped, because accessibility
 * events fire many times per second and a chat list can contain thousands of nodes.
 */
object UrlExtractor {

    private const val MAX_NODES = 1_200
    private const val MAX_DEPTH = 60
    private const val MAX_URLS = 6
    private const val MAX_CLICK_CHILDREN = 12
    private const val MIN_CONTEXT_LENGTH = 12
    private const val MAX_CONTEXT_LENGTH = 300

    /** View-id fragments used by the major browsers for their address bar. */
    private val ADDRESS_BAR_HINTS = listOf("url", "omnibox", "address", "location")

    data class WindowScan(
        val urls: List<String>,
        val contextText: String?
    )

    private data class NodeDepth(val node: AccessibilityNodeInfo, val depth: Int)

    /**
     * Collects URLs from an entire window plus the longest visible text block, which is passed to
     * the AI layer as surrounding context (the message the link arrived in).
     *
     * @param addressBarOnly when true only the browser address bar is inspected. Scanning the whole
     *   page would flag links that merely *appear* in an article or a search result, so browsers
     *   are limited to the URL the user is actually on; link taps are still covered separately by
     *   [aroundNode].
     */
    fun scanWindow(root: AccessibilityNodeInfo?, addressBarOnly: Boolean = false): WindowScan {
        if (root == null) return WindowScan(emptyList(), null)

        val urls = LinkedHashSet<String>()
        var contextText: String? = null
        var contextLength = MIN_CONTEXT_LENGTH

        val queue = ArrayDeque<NodeDepth>()
        queue.add(NodeDepth(root, 0))
        var visited = 0

        while (queue.isNotEmpty() && visited < MAX_NODES && urls.size < MAX_URLS) {
            val (node, depth) = queue.removeFirst()
            visited++

            val inspectable = !addressBarOnly || isAddressBar(node)
            val text = node.text?.toString()?.trim()
            if (inspectable && !text.isNullOrEmpty()) {
                if (text.length > contextLength && text.length <= MAX_CONTEXT_LENGTH) {
                    contextText = text
                    contextLength = text.length
                }
                collect(text, urls)
            }
            if (inspectable) {
                node.contentDescription?.toString()?.let { collect(it, urls) }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    node.hintText?.toString()?.let { collect(it, urls) }
                }
            }

            if (depth >= MAX_DEPTH) continue
            for (index in 0 until node.childCount) {
                val child = node.getChild(index) ?: continue
                queue.add(NodeDepth(child, depth + 1))
            }
        }

        return WindowScan(urls.toList(), contextText)
    }

    private fun isAddressBar(node: AccessibilityNodeInfo): Boolean {
        if (node.isEditable || node.isFocused) return true
        val viewId = node.viewIdResourceName?.lowercase(Locale.ROOT) ?: return false
        return ADDRESS_BAR_HINTS.any { viewId.contains(it) }
    }

    /** Text attached to an event, useful for `TYPE_VIEW_TEXT_CHANGED` and click events. */
    fun fromEvent(event: AccessibilityEvent): List<String> {
        if (event.text.isNullOrEmpty()) return emptyList()
        val builder = StringBuilder()
        event.text.forEach { builder.append(it).append(' ') }
        return UrlTextParser.findUrls(builder.toString())
    }

    /**
     * URLs near a clicked node: the node itself, its children (some apps put the link in a nested
     * TextView) and up to two parents (others put it on a clickable row).
     */
    fun aroundNode(node: AccessibilityNodeInfo?): List<String> {
        if (node == null) return emptyList()
        val urls = LinkedHashSet<String>()
        var cursor: AccessibilityNodeInfo? = node
        var depth = 0

        while (cursor != null && depth < 3 && urls.size < 4) {
            cursor.text?.toString()?.let { collect(it, urls) }
            cursor.contentDescription?.toString()?.let { collect(it, urls) }

            if (urls.isEmpty() && cursor.childCount in 1..MAX_CLICK_CHILDREN) {
                for (index in 0 until cursor.childCount) {
                    val child = cursor.getChild(index) ?: continue
                    child.text?.toString()?.let { collect(it, urls) }
                    child.contentDescription?.toString()?.let { collect(it, urls) }
                }
            }

            cursor = cursor.parent
            depth++
        }
        return urls.toList()
    }

    private fun collect(rawText: String, into: MutableSet<String>) {
        if (rawText.isBlank() || into.size >= MAX_URLS) return
        for (url in UrlTextParser.findUrls(rawText, limit = MAX_URLS)) {
            into.add(url)
            if (into.size >= MAX_URLS) return
        }
    }
}
